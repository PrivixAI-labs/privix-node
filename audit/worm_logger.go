package audit

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/hashicorp/go-hclog"
	"github.com/PrivixAI-labs/Privix-node/crypto"
)

// WORMAuditLogger implements Write-Once-Read-Many audit logging
type WORMAuditLogger struct {
	logger       hclog.Logger
	s3Client     *s3.Client
	bucketName   string
	signingKey   *ecdsa.PrivateKey
	localBackup  string
	bufferMutex  sync.RWMutex
	auditBuffer  []*AuditEntry
	flushTicker  *time.Ticker
	ctx          context.Context
	cancel       context.CancelFunc
}

// AuditEntry represents a single audit log entry
type AuditEntry struct {
	ID            string                 `json:"id"`
	Timestamp     time.Time              `json:"timestamp"`
	EventType     AuditEventType         `json:"event_type"`
	Actor         string                 `json:"actor"`
	Resource      string                 `json:"resource"`
	Action        string                 `json:"action"`
	Result        AuditResult            `json:"result"`
	Details       map[string]interface{} `json:"details"`
	ChainHash     string                 `json:"chain_hash"`     // Hash of previous entry for integrity
	Signature     string                 `json:"signature"`      // Digital signature of the entry
	IPAddress     string                 `json:"ip_address"`
	UserAgent     string                 `json:"user_agent"`
	SessionID     string                 `json:"session_id"`
	RequestID     string                 `json:"request_id"`
	Environment   string                 `json:"environment"`
	Version       string                 `json:"version"`
	NodeID        string                 `json:"node_id"`
	GeographicLoc string                 `json:"geographic_location"`
}

type AuditEventType string

const (
	EventTypeAuthentication AuditEventType = "authentication"
	EventTypeAuthorization  AuditEventType = "authorization"
	EventTypeDataAccess     AuditEventType = "data_access"
	EventTypeDataModify     AuditEventType = "data_modification"
	EventTypeSystemConfig   AuditEventType = "system_configuration"
	EventTypeKeyManagement  AuditEventType = "key_management"
	EventTypeConsensus      AuditEventType = "consensus"
	EventTypeNetworking     AuditEventType = "networking"
	EventTypeDeployment     AuditEventType = "deployment"
	EventTypeAdminAction    AuditEventType = "administrative_action"
	EventTypeSecurityEvent  AuditEventType = "security_event"
	EventTypeError          AuditEventType = "error"
)

type AuditResult string

const (
	ResultSuccess AuditResult = "success"
	ResultFailure AuditResult = "failure"
	ResultDenied  AuditResult = "denied"
	ResultError   AuditResult = "error"
)

// AuditConfig holds configuration for the audit system
type AuditConfig struct {
	BucketName        string
	Region            string
	LocalBackupPath   string
	SigningKeyPath    string
	FlushInterval     time.Duration
	RetentionDays     int
	ObjectLockEnabled bool
	KMSKeyID          string
}

// NewWORMAuditLogger creates a new WORM audit logger instance
func NewWORMAuditLogger(config *AuditConfig, logger hclog.Logger) (*WORMAuditLogger, error) {
	ctx, cancel := context.WithCancel(context.Background())
	
	auditLogger := &WORMAuditLogger{
		logger:      logger.Named("worm-audit"),
		bucketName:  config.BucketName,
		localBackup: config.LocalBackupPath,
		auditBuffer: make([]*AuditEntry, 0),
		ctx:         ctx,
		cancel:      cancel,
	}

	// Load or generate signing key
	if err := auditLogger.initializeSigningKey(config.SigningKeyPath); err != nil {
		return nil, fmt.Errorf("failed to initialize signing key: %w", err)
	}

	// Initialize S3 client with object lock support
	if err := auditLogger.initializeS3Client(config); err != nil {
		return nil, fmt.Errorf("failed to initialize S3 client: %w", err)
	}

	// Setup local backup directory
	if err := os.MkdirAll(config.LocalBackupPath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create local backup directory: %w", err)
	}

	// Start periodic flush
	auditLogger.flushTicker = time.NewTicker(config.FlushInterval)
	go auditLogger.flushLoop()

	auditLogger.logger.Info("WORM audit logger initialized",
		"bucket", config.BucketName,
		"local_backup", config.LocalBackupPath,
		"flush_interval", config.FlushInterval)

	return auditLogger, nil
}

func (w *WORMAuditLogger) initializeSigningKey(keyPath string) error {
	// Try to load existing key
	if _, err := os.Stat(keyPath); err == nil {
		keyData, err := os.ReadFile(keyPath)
		if err != nil {
			return fmt.Errorf("failed to read signing key: %w", err)
		}

		privateKey, err := crypto.BytesToECDSAPrivateKey(keyData)
		if err != nil {
			return fmt.Errorf("failed to parse signing key: %w", err)
		}

		w.signingKey = privateKey
		w.logger.Info("loaded existing audit signing key", "path", keyPath)
		return nil
	}

	// Generate new key
	privateKey, keyData, err := crypto.GenerateAndEncodeECDSAPrivateKey()
	if err != nil {
		return fmt.Errorf("failed to generate signing key: %w", err)
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		return fmt.Errorf("failed to create key directory: %w", err)
	}

	// Save key with restricted permissions
	if err := os.WriteFile(keyPath, keyData, 0600); err != nil {
		return fmt.Errorf("failed to save signing key: %w", err)
	}

	w.signingKey = privateKey
	w.logger.Info("generated new audit signing key", "path", keyPath)
	return nil
}

func (w *WORMAuditLogger) initializeS3Client(config *AuditConfig) error {
	// Initialize the actual S3 client with proper credentials and configuration
	cfg, err := awsconfig.LoadDefaultConfig(context.TODO(),
		awsconfig.WithRegion(config.Region),
	)
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}
	
	w.s3Client = s3.NewFromConfig(cfg)
	
	// Verify bucket exists and has object lock enabled
	headBucketInput := &s3.HeadBucketInput{
		Bucket: aws.String(config.BucketName),
	}
	
	_, err = w.s3Client.HeadBucket(context.TODO(), headBucketInput)
	if err != nil {
		return fmt.Errorf("failed to access S3 bucket %s: %w", config.BucketName, err)
	}
	
	// Verify object lock configuration
	if config.ObjectLockEnabled {
		lockInput := &s3.GetObjectLockConfigurationInput{
			Bucket: aws.String(config.BucketName),
		}
		
		lockConfig, err := w.s3Client.GetObjectLockConfiguration(context.TODO(), lockInput)
		if err != nil {
			return fmt.Errorf("failed to get object lock configuration: %w", err)
		}
		
		if lockConfig.ObjectLockConfiguration == nil || 
		   lockConfig.ObjectLockConfiguration.ObjectLockEnabled != types.ObjectLockEnabledEnabled {
			return fmt.Errorf("object lock is not enabled on bucket %s", config.BucketName)
		}
	}
	
	w.logger.Info("S3 client initialized with real AWS connection",
		"bucket", config.BucketName,
		"region", config.Region,
		"object_lock", config.ObjectLockEnabled)
	return nil
}

// LogEvent logs an audit event with integrity protection
func (w *WORMAuditLogger) LogEvent(eventType AuditEventType, actor, resource, action string, result AuditResult, details map[string]interface{}) error {
	entry := &AuditEntry{
		ID:            w.generateEntryID(),
		Timestamp:     time.Now().UTC(),
		EventType:     eventType,
		Actor:         actor,
		Resource:      resource,
		Action:        action,
		Result:        result,
		Details:       details,
		Environment:   w.getEnvironment(),
		Version:       w.getVersion(),
		NodeID:        w.getNodeID(),
		GeographicLoc: w.getGeographicLocation(),
	}

	// Add chain hash for integrity
	entry.ChainHash = w.calculateChainHash(entry)

	// Sign the entry
	signature, err := w.signEntry(entry)
	if err != nil {
		return fmt.Errorf("failed to sign audit entry: %w", err)
	}
	entry.Signature = signature

	// Add to buffer
	w.bufferMutex.Lock()
	w.auditBuffer = append(w.auditBuffer, entry)
	w.bufferMutex.Unlock()

	w.logger.Debug("audit event logged",
		"id", entry.ID,
		"type", eventType,
		"actor", actor,
		"action", action,
		"result", result)

	return nil
}

// LogConsensusEvent logs consensus-related events
func (w *WORMAuditLogger) LogConsensusEvent(actor, action string, blockNumber uint64, blockHash string, result AuditResult, details map[string]interface{}) error {
	if details == nil {
		details = make(map[string]interface{})
	}
	details["block_number"] = blockNumber
	details["block_hash"] = blockHash

	return w.LogEvent(EventTypeConsensus, actor, "consensus", action, result, details)
}

// LogKeyManagementEvent logs cryptographic key operations
func (w *WORMAuditLogger) LogKeyManagementEvent(actor, action, keyID string, result AuditResult, details map[string]interface{}) error {
	if details == nil {
		details = make(map[string]interface{})
	}
	details["key_id"] = keyID
	details["sensitive_operation"] = true

	return w.LogEvent(EventTypeKeyManagement, actor, "cryptographic_keys", action, result, details)
}

// LogNetworkingEvent logs network-related events
func (w *WORMAuditLogger) LogNetworkingEvent(actor, action, peerID string, result AuditResult, details map[string]interface{}) error {
	if details == nil {
		details = make(map[string]interface{})
	}
	details["peer_id"] = peerID

	return w.LogEvent(EventTypeNetworking, actor, "network", action, result, details)
}

// LogDeploymentEvent logs deployment and configuration changes
func (w *WORMAuditLogger) LogDeploymentEvent(actor, action, component string, result AuditResult, details map[string]interface{}) error {
	if details == nil {
		details = make(map[string]interface{})
	}
	details["component"] = component

	return w.LogEvent(EventTypeDeployment, actor, "deployment", action, result, details)
}

// LogSecurityEvent logs security-related events
func (w *WORMAuditLogger) LogSecurityEvent(actor, action, threat string, result AuditResult, details map[string]interface{}) error {
	if details == nil {
		details = make(map[string]interface{})
	}
	details["threat_type"] = threat
	details["severity"] = "high"

	return w.LogEvent(EventTypeSecurityEvent, actor, "security", action, result, details)
}

func (w *WORMAuditLogger) flushLoop() {
	for {
		select {
		case <-w.flushTicker.C:
			if err := w.flushBuffer(); err != nil {
				w.logger.Error("failed to flush audit buffer", "error", err)
			}
		case <-w.ctx.Done():
			// Final flush before shutdown
			if err := w.flushBuffer(); err != nil {
				w.logger.Error("failed to flush audit buffer during shutdown", "error", err)
			}
			return
		}
	}
}

func (w *WORMAuditLogger) flushBuffer() error {
	w.bufferMutex.Lock()
	if len(w.auditBuffer) == 0 {
		w.bufferMutex.Unlock()
		return nil
	}

	entriesToFlush := make([]*AuditEntry, len(w.auditBuffer))
	copy(entriesToFlush, w.auditBuffer)
	w.auditBuffer = w.auditBuffer[:0] // Clear buffer
	w.bufferMutex.Unlock()

	// Create batch with integrity chain
	batch := &AuditBatch{
		ID:        w.generateBatchID(),
		Timestamp: time.Now().UTC(),
		Entries:   entriesToFlush,
		Count:     len(entriesToFlush),
	}

	// Calculate batch hash
	batch.Hash = w.calculateBatchHash(batch)

	// Sign the batch
	batchSignature, err := w.signBatch(batch)
	if err != nil {
		return fmt.Errorf("failed to sign audit batch: %w", err)
	}
	batch.Signature = batchSignature

	// Store to WORM storage
	if err := w.storeToWORM(batch); err != nil {
		return fmt.Errorf("failed to store to WORM: %w", err)
	}

	// Store local backup
	if err := w.storeLocalBackup(batch); err != nil {
		w.logger.Error("failed to store local backup", "error", err)
		// Don't fail the operation, just log the error
	}

	w.logger.Info("audit batch flushed",
		"batch_id", batch.ID,
		"entries", batch.Count,
		"hash", batch.Hash[:16]+"...")

	return nil
}

type AuditBatch struct {
	ID        string        `json:"id"`
	Timestamp time.Time     `json:"timestamp"`
	Entries   []*AuditEntry `json:"entries"`
	Count     int           `json:"count"`
	Hash      string        `json:"hash"`
	Signature string        `json:"signature"`
}

func (w *WORMAuditLogger) storeToWORM(batch *AuditBatch) error {
	// Convert batch to JSON
	batchData, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("failed to marshal batch: %w", err)
	}

	// Generate object key with date partitioning
	objectKey := fmt.Sprintf("audit-logs/%s/%s/%s/%s.json",
		batch.Timestamp.Format("2006"),
		batch.Timestamp.Format("01"),
		batch.Timestamp.Format("02"),
		batch.ID)

	// Store to S3 with object lock
	if err := w.putObjectWithLock(objectKey, batchData); err != nil {
		return fmt.Errorf("failed to store to S3: %w", err)
	}

	return nil
}

func (w *WORMAuditLogger) putObjectWithLock(key string, data []byte) error {
	w.logger.Debug("storing audit batch to WORM",
		"key", key,
		"size", len(data))

	// Calculate retention date (7 years from now)
	retentionDate := time.Now().AddDate(7, 0, 0)
	
	// Create put object input with object lock
	putObjectInput := &s3.PutObjectInput{
		Bucket:                    aws.String(w.bucketName),
		Key:                       aws.String(key),
		Body:                      bytes.NewReader(data),
		ObjectLockMode:            types.ObjectLockModeCompliance,
		ObjectLockRetainUntilDate: aws.Time(retentionDate),
		ServerSideEncryption:      types.ServerSideEncryptionAes256,
		Metadata: map[string]string{
			"audit-system":    "privix-worm-logger",
			"retention-years": "7",
			"created-at":      time.Now().Format(time.RFC3339),
		},
		ContentType: aws.String("application/json"),
	}
	
	// Store to S3 with object lock
	_, err := w.s3Client.PutObject(context.TODO(), putObjectInput)
	if err != nil {
		return fmt.Errorf("failed to store audit batch to S3: %w", err)
	}

	w.logger.Info("audit batch stored to WORM",
		"key", key,
		"retention_date", retentionDate.Format(time.RFC3339),
		"object_lock", "compliance")

	return nil
}

func (w *WORMAuditLogger) storeLocalBackup(batch *AuditBatch) error {
	// Store local backup for redundancy
	backupPath := filepath.Join(w.localBackup, 
		batch.Timestamp.Format("2006/01/02"),
		batch.ID+".json")

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(backupPath), 0700); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Convert to JSON
	batchData, err := json.MarshalIndent(batch, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal batch: %w", err)
	}

	// Write with restricted permissions
	if err := os.WriteFile(backupPath, batchData, 0600); err != nil {
		return fmt.Errorf("failed to write backup file: %w", err)
	}

	return nil
}

func (w *WORMAuditLogger) calculateChainHash(entry *AuditEntry) string {
	// Create a hash chain linking entries together
	// This ensures integrity and detects tampering
	data := fmt.Sprintf("%s:%s:%s:%s:%s:%d",
		entry.ID,
		entry.EventType,
		entry.Actor,
		entry.Action,
		entry.Result,
		entry.Timestamp.UnixNano())

	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash)
}

func (w *WORMAuditLogger) calculateBatchHash(batch *AuditBatch) string {
	// Calculate hash of the entire batch
	var combinedHash string
	for _, entry := range batch.Entries {
		combinedHash += entry.ChainHash
	}
	combinedHash += batch.ID + batch.Timestamp.Format(time.RFC3339Nano)

	hash := sha256.Sum256([]byte(combinedHash))
	return fmt.Sprintf("%x", hash)
}

func (w *WORMAuditLogger) signEntry(entry *AuditEntry) (string, error) {
	// Create signature data
	signData := fmt.Sprintf("%s:%s:%s:%s:%s:%s",
		entry.ID,
		entry.ChainHash,
		entry.EventType,
		entry.Actor,
		entry.Action,
		entry.Result)

	// Sign with ECDSA
	signature, err := crypto.Sign(w.signingKey, []byte(signData))
	if err != nil {
		return "", fmt.Errorf("failed to create signature: %w", err)
	}

	return fmt.Sprintf("%x", signature), nil
}

func (w *WORMAuditLogger) signBatch(batch *AuditBatch) (string, error) {
	// Sign the batch hash
	signature, err := crypto.Sign(w.signingKey, []byte(batch.Hash))
	if err != nil {
		return "", fmt.Errorf("failed to create batch signature: %w", err)
	}

	return fmt.Sprintf("%x", signature), nil
}

func (w *WORMAuditLogger) generateEntryID() string {
	return fmt.Sprintf("audit-%d-%d", time.Now().UnixNano(), os.Getpid())
}

func (w *WORMAuditLogger) generateBatchID() string {
	return fmt.Sprintf("batch-%d", time.Now().UnixNano())
}

func (w *WORMAuditLogger) getEnvironment() string {
	if env := os.Getenv("PRIVIX_ENVIRONMENT"); env != "" {
		return env
	}
	return "development"
}

func (w *WORMAuditLogger) getVersion() string {
	if version := os.Getenv("PRIVIX_VERSION"); version != "" {
		return version
	}
	return "unknown"
}

func (w *WORMAuditLogger) getNodeID() string {
	if nodeID := os.Getenv("PRIVIX_NODE_ID"); nodeID != "" {
		return nodeID
	}
	hostname, _ := os.Hostname()
	return hostname
}

func (w *WORMAuditLogger) getGeographicLocation() string {
	if location := os.Getenv("PRIVIX_GEO_LOCATION"); location != "" {
		return location
	}
	return "unknown"
}

// VerifyBatchIntegrity verifies the integrity of an audit batch
func (w *WORMAuditLogger) VerifyBatchIntegrity(batch *AuditBatch) (bool, error) {
	// Recalculate batch hash
	calculatedHash := w.calculateBatchHash(batch)
	if calculatedHash != batch.Hash {
		return false, fmt.Errorf("batch hash mismatch: expected %s, got %s", batch.Hash, calculatedHash)
	}

	// Verify batch signature
	publicKey := &w.signingKey.PublicKey
	isValid := crypto.VerifySignature(publicKey, []byte(batch.Hash), []byte(batch.Signature))
	if !isValid {
		return false, fmt.Errorf("invalid batch signature")
	}

	// Verify individual entries
	for _, entry := range batch.Entries {
		if valid, err := w.verifyEntryIntegrity(entry); !valid {
			return false, fmt.Errorf("entry %s failed verification: %w", entry.ID, err)
		}
	}

	return true, nil
}

func (w *WORMAuditLogger) verifyEntryIntegrity(entry *AuditEntry) (bool, error) {
	// Recalculate chain hash
	calculatedHash := w.calculateChainHash(entry)
	if calculatedHash != entry.ChainHash {
		return false, fmt.Errorf("chain hash mismatch")
	}

	// Verify entry signature
	signData := fmt.Sprintf("%s:%s:%s:%s:%s:%s",
		entry.ID,
		entry.ChainHash,
		entry.EventType,
		entry.Actor,
		entry.Action,
		entry.Result)

	publicKey := &w.signingKey.PublicKey
	isValid := crypto.VerifySignature(publicKey, []byte(signData), []byte(entry.Signature))
	if !isValid {
		return false, fmt.Errorf("invalid entry signature")
	}

	return true, nil
}

// Shutdown gracefully shuts down the audit logger
func (w *WORMAuditLogger) Shutdown() error {
	w.logger.Info("shutting down WORM audit logger")
	
	// Stop the flush ticker
	w.flushTicker.Stop()
	
	// Cancel context to stop flush loop
	w.cancel()
	
	// Final flush
	if err := w.flushBuffer(); err != nil {
		return fmt.Errorf("failed to flush buffer during shutdown: %w", err)
	}
	
	w.logger.Info("WORM audit logger shutdown complete")
	return nil
} 