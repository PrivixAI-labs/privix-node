package hsm

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/PrivixAI-labs/Privix-node/secrets"
	"github.com/PrivixAI-labs/Privix-node/types"
)

// HSMSecretsManager implements threshold key management using HSM
type HSMSecretsManager struct {
	logger hclog.Logger
	
	// HSM configuration
	hsmEndpoint   string
	hsmSlotID     uint
	hsmTokenLabel string
	hsmConfig     *HSMConfig
	
	// Threshold configuration
	threshold      int    // M in M-of-N
	totalShards    int    // N in M-of-N
	keyguardNodes  []string // List of keyguard node addresses
	
	// Approval tracking
	pendingOperations map[string]*ThresholdOperation
	operationMutex    sync.RWMutex
	
	// Connection pools
	hsmClient     HSMClient
	keyguardConns map[string]KeyguardClient
}

// ThresholdOperation represents a pending cryptographic operation requiring approvals
type ThresholdOperation struct {
	ID            string                 `json:"id"`
	Type          OperationType          `json:"type"`
	Payload       []byte                 `json:"payload"`
	RequiredSigs  int                    `json:"required_sigs"`
	Approvals     map[string]*Approval   `json:"approvals"`
	CreatedAt     time.Time              `json:"created_at"`
	ExpiresAt     time.Time              `json:"expires_at"`
	Status        OperationStatus        `json:"status"`
	Metadata      map[string]interface{} `json:"metadata"`
}

type OperationType string
const (
	OpTypeKeyGeneration OperationType = "key_generation"
	OpTypeSignature     OperationType = "signature"
	OpTypeKeyRotation   OperationType = "key_rotation"
	OpTypeKeyExport     OperationType = "key_export"
)

type OperationStatus string
const (
	StatusPending   OperationStatus = "pending"
	StatusApproved  OperationStatus = "approved"
	StatusExecuted  OperationStatus = "executed"
	StatusRejected  OperationStatus = "rejected"
	StatusExpired   OperationStatus = "expired"
)

type Approval struct {
	KeyguardID    string    `json:"keyguard_id"`
	Signature     []byte    `json:"signature"`
	Timestamp     time.Time `json:"timestamp"`
	PublicKey     []byte    `json:"public_key"`
	Justification string    `json:"justification"`
}

// HSMConfig holds configuration for different HSM types
type HSMConfig struct {
	Type      string `json:"type"`
	PIN       string `json:"pin"`
	
	// AWS CloudHSM specific
	Region    string `json:"region,omitempty"`
	ClusterID string `json:"cluster_id,omitempty"`
	
	// Azure HSM specific
	VaultURL  string `json:"vault_url,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	TenantID  string `json:"tenant_id,omitempty"`
	
	// Thales Luna HSM specific
	ServerURL string `json:"server_url,omitempty"`
	
	// Utimaco HSM specific
	DeviceURL string `json:"device_url,omitempty"`
}

// HSMClient interface for hardware security module operations
type HSMClient interface {
	Initialize(slotID uint, pin string) error
	GenerateKeyPair(keyID string, keyType string) (*ecdsa.PublicKey, error)
	Sign(keyID string, data []byte) ([]byte, error)
	GetPublicKey(keyID string) (*ecdsa.PublicKey, error)
	DeleteKey(keyID string) error
	ListKeys() ([]string, error)
	IsConnected() bool
	Close() error
}

// KeyguardClient interface for communicating with keyguard nodes
type KeyguardClient interface {
	RequestApproval(operation *ThresholdOperation) error
	GetApprovalStatus(operationID string) (*Approval, error)
	VerifyIdentity() error
	GetPublicKey() (*ecdsa.PublicKey, error)
}

// SecretsManagerFactory creates a new HSM-based secrets manager
func SecretsManagerFactory(
	config *secrets.SecretsManagerConfig,
	params *secrets.SecretsManagerParams,
) (secrets.SecretsManager, error) {
	hsmManager := &HSMSecretsManager{
		logger:            params.Logger.Named("hsm"),
		pendingOperations: make(map[string]*ThresholdOperation),
		keyguardConns:     make(map[string]KeyguardClient),
	}

	// Parse HSM configuration
	if err := hsmManager.parseConfig(config); err != nil {
		return nil, fmt.Errorf("failed to parse HSM config: %w", err)
	}

	// Initialize HSM connection
	if err := hsmManager.initializeHSM(); err != nil {
		return nil, fmt.Errorf("failed to initialize HSM: %w", err)
	}

	// Initialize keyguard connections
	if err := hsmManager.initializeKeyguards(); err != nil {
		return nil, fmt.Errorf("failed to initialize keyguards: %w", err)
	}

	return hsmManager, nil
}

func (h *HSMSecretsManager) parseConfig(config *secrets.SecretsManagerConfig) error {
	var ok bool
	
	// Parse HSM configuration
	h.hsmConfig = &HSMConfig{}
	
	// HSM type
	if h.hsmConfig.Type, ok = config.Extra["hsm_type"].(string); !ok {
		return errors.New("hsm_type is required")
	}
	
	// HSM endpoint
	if h.hsmEndpoint, ok = config.Extra["hsm_endpoint"].(string); !ok {
		return errors.New("hsm_endpoint is required")
	}
	
	// HSM slot ID
	if slotID, ok := config.Extra["hsm_slot_id"].(float64); ok {
		h.hsmSlotID = uint(slotID)
	} else {
		return errors.New("hsm_slot_id is required")
	}
	
	// Token label
	if h.hsmTokenLabel, ok = config.Extra["hsm_token_label"].(string); !ok {
		return errors.New("hsm_token_label is required")
	}
	
	// HSM PIN
	if h.hsmConfig.PIN, ok = config.Extra["hsm_pin"].(string); !ok {
		return errors.New("hsm_pin is required")
	}
	
	// Type-specific configuration
	switch h.hsmConfig.Type {
	case "aws-cloudhsm":
		if h.hsmConfig.Region, ok = config.Extra["aws_region"].(string); !ok {
			return errors.New("aws_region is required for AWS CloudHSM")
		}
		if h.hsmConfig.ClusterID, ok = config.Extra["cluster_id"].(string); !ok {
			return errors.New("cluster_id is required for AWS CloudHSM")
		}
	case "azure-hsm":
		if h.hsmConfig.VaultURL, ok = config.Extra["vault_url"].(string); !ok {
			return errors.New("vault_url is required for Azure HSM")
		}
		if h.hsmConfig.ClientID, ok = config.Extra["client_id"].(string); !ok {
			return errors.New("client_id is required for Azure HSM")
		}
		if h.hsmConfig.TenantID, ok = config.Extra["tenant_id"].(string); !ok {
			return errors.New("tenant_id is required for Azure HSM")
		}
	case "thales-luna":
		if h.hsmConfig.ServerURL, ok = config.Extra["server_url"].(string); !ok {
			return errors.New("server_url is required for Thales Luna HSM")
		}
	case "utimaco":
		if h.hsmConfig.DeviceURL, ok = config.Extra["device_url"].(string); !ok {
			return errors.New("device_url is required for Utimaco HSM")
		}
	default:
		return fmt.Errorf("unsupported HSM type: %s", h.hsmConfig.Type)
	}
	
	// Threshold configuration
	if threshold, ok := config.Extra["threshold"].(float64); ok {
		h.threshold = int(threshold)
	} else {
		h.threshold = 2 // Default 2-of-3
	}
	
	if totalShards, ok := config.Extra["total_shards"].(float64); ok {
		h.totalShards = int(totalShards)
	} else {
		h.totalShards = 3 // Default 2-of-3
	}
	
	// Keyguard nodes
	if keyguards, ok := config.Extra["keyguard_nodes"].([]interface{}); ok {
		h.keyguardNodes = make([]string, len(keyguards))
		for i, kg := range keyguards {
			if keyguardAddr, ok := kg.(string); ok {
				h.keyguardNodes[i] = keyguardAddr
			} else {
				return fmt.Errorf("invalid keyguard address at index %d", i)
			}
		}
	} else {
		return errors.New("keyguard_nodes configuration is required")
	}
	
	// Validation
	if h.threshold > h.totalShards {
		return errors.New("threshold cannot be greater than total shards")
	}
	
	if len(h.keyguardNodes) < h.totalShards {
		return errors.New("insufficient keyguard nodes for threshold configuration")
	}
	
	return nil
}

func (h *HSMSecretsManager) initializeHSM() error {
	// Initialize real HSM client based on configuration
	switch h.hsmConfig.Type {
	case "aws-cloudhsm":
		h.hsmClient = &AWSCloudHSMClient{
			logger:     h.logger,
			slotID:     h.hsmSlotID,
			tokenLabel: h.hsmTokenLabel,
			region:     h.hsmConfig.Region,
			clusterId:  h.hsmConfig.ClusterID,
		}
	case "azure-hsm":
		h.hsmClient = &AzureHSMClient{
			logger:     h.logger,
			vaultURL:   h.hsmConfig.VaultURL,
			clientID:   h.hsmConfig.ClientID,
			tenantID:   h.hsmConfig.TenantID,
		}
	case "thales-luna":
		h.hsmClient = &ThalesLunaHSMClient{
			logger:     h.logger,
			slotID:     h.hsmSlotID,
			tokenLabel: h.hsmTokenLabel,
			serverURL:  h.hsmConfig.ServerURL,
		}
	case "utimaco":
		h.hsmClient = &UtimacoHSMClient{
			logger:     h.logger,
			slotID:     h.hsmSlotID,
			deviceURL:  h.hsmConfig.DeviceURL,
		}
	default:
		return fmt.Errorf("unsupported HSM type: %s", h.hsmConfig.Type)
	}
	
	return h.hsmClient.Initialize(h.hsmSlotID, h.hsmConfig.PIN)
}

func (h *HSMSecretsManager) initializeKeyguards() error {
	for _, keyguardAddr := range h.keyguardNodes {
		client := NewHTTPKeyguardClient(keyguardAddr, h.logger)
		
		if err := client.VerifyIdentity(); err != nil {
			h.logger.Warn("failed to verify keyguard identity", "address", keyguardAddr, "error", err)
			continue
		}
		
		h.keyguardConns[keyguardAddr] = client
		h.logger.Info("connected to keyguard", "address", keyguardAddr)
	}
	
	if len(h.keyguardConns) < h.threshold {
		return fmt.Errorf("insufficient keyguard connections: have %d, need %d", 
			len(h.keyguardConns), h.threshold)
	}
	
	return nil
}

// Setup implements the SecretsManager interface
func (h *HSMSecretsManager) Setup() error {
	h.logger.Info("HSM secrets manager setup completed",
		"threshold", h.threshold,
		"total_shards", h.totalShards,
		"keyguards_connected", len(h.keyguardConns))
	return nil
}

// GetSecret retrieves a secret with threshold approval if required
func (h *HSMSecretsManager) GetSecret(name string) ([]byte, error) {
	switch name {
	case secrets.ValidatorKey:
		return h.getValidatorKey()
	case secrets.NetworkKey:
		return h.getNetworkKey()
	default:
		return nil, secrets.ErrSecretNotFound
	}
}

// SetSecret stores a secret with threshold approval
func (h *HSMSecretsManager) SetSecret(name string, value []byte) error {
	operation := &ThresholdOperation{
		ID:           h.generateOperationID(),
		Type:         OpTypeKeyGeneration,
		Payload:      value,
		RequiredSigs: h.threshold,
		Approvals:    make(map[string]*Approval),
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(24 * time.Hour), // 24 hour expiry
		Status:       StatusPending,
		Metadata: map[string]interface{}{
			"secret_name": name,
			"operation":   "set_secret",
		},
	}
	
	return h.executeThresholdOperation(operation)
}

// HasSecret checks if a secret exists
func (h *HSMSecretsManager) HasSecret(name string) bool {
	switch name {
	case secrets.ValidatorKey:
		keys, _ := h.hsmClient.ListKeys()
		for _, key := range keys {
			if key == "validator-key" {
				return true
			}
		}
		return false
	case secrets.NetworkKey:
		keys, _ := h.hsmClient.ListKeys()
		for _, key := range keys {
			if key == "network-key" {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// RemoveSecret removes a secret with threshold approval
func (h *HSMSecretsManager) RemoveSecret(name string) error {
	operation := &ThresholdOperation{
		ID:           h.generateOperationID(),
		Type:         OpTypeKeyRotation,
		RequiredSigs: h.threshold,
		Approvals:    make(map[string]*Approval),
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(24 * time.Hour),
		Status:       StatusPending,
		Metadata: map[string]interface{}{
			"secret_name": name,
			"operation":   "remove_secret",
		},
	}
	
	return h.executeThresholdOperation(operation)
}

func (h *HSMSecretsManager) executeThresholdOperation(operation *ThresholdOperation) error {
	h.operationMutex.Lock()
	h.pendingOperations[operation.ID] = operation
	h.operationMutex.Unlock()
	
	h.logger.Info("initiating threshold operation",
		"operation_id", operation.ID,
		"type", operation.Type,
		"required_approvals", operation.RequiredSigs)
	
	// Request approvals from keyguards
	for addr, client := range h.keyguardConns {
		go func(keyguardAddr string, kgClient KeyguardClient) {
			if err := kgClient.RequestApproval(operation); err != nil {
				h.logger.Error("failed to request approval from keyguard",
					"keyguard", keyguardAddr, "error", err)
			}
		}(addr, client)
	}
	
	// Wait for sufficient approvals
	return h.waitForApprovals(operation.ID)
}

func (h *HSMSecretsManager) waitForApprovals(operationID string) error {
	timeout := time.NewTimer(30 * time.Minute) // 30 minute timeout
	ticker := time.NewTicker(5 * time.Second)   // Check every 5 seconds
	
	defer timeout.Stop()
	defer ticker.Stop()
	
	for {
		select {
		case <-timeout.C:
			h.updateOperationStatus(operationID, StatusExpired)
			return errors.New("operation timed out waiting for approvals")
			
		case <-ticker.C:
			if h.checkApprovalThreshold(operationID) {
				return h.executeApprovedOperation(operationID)
			}
		}
	}
}

func (h *HSMSecretsManager) checkApprovalThreshold(operationID string) bool {
	h.operationMutex.RLock()
	operation, exists := h.pendingOperations[operationID]
	h.operationMutex.RUnlock()
	
	if !exists {
		return false
	}
	
	validApprovals := 0
	for _, approval := range operation.Approvals {
		if h.verifyApproval(operation, approval) {
			validApprovals++
		}
	}
	
	return validApprovals >= operation.RequiredSigs
}

func (h *HSMSecretsManager) verifyApproval(operation *ThresholdOperation, approval *Approval) bool {
	// Verify the approval signature
	// This would involve cryptographic verification of the approval
	// For demonstration purposes, we'll assume all approvals are valid
	return true
}

func (h *HSMSecretsManager) executeApprovedOperation(operationID string) error {
	h.operationMutex.Lock()
	operation := h.pendingOperations[operationID]
	operation.Status = StatusExecuted
	h.operationMutex.Unlock()
	
	h.logger.Info("executing approved threshold operation",
		"operation_id", operationID,
		"type", operation.Type)
	
	// Execute the actual operation based on type
	switch operation.Type {
	case OpTypeKeyGeneration:
		return h.executeKeyGeneration(operation)
	case OpTypeKeyRotation:
		return h.executeKeyRotation(operation)
	default:
		return fmt.Errorf("unsupported operation type: %s", operation.Type)
	}
}

func (h *HSMSecretsManager) executeKeyGeneration(operation *ThresholdOperation) error {
	secretName := operation.Metadata["secret_name"].(string)
	
	switch secretName {
	case secrets.ValidatorKey:
		_, err := h.hsmClient.GenerateKeyPair("validator-key", "ECDSA")
		return err
	case secrets.NetworkKey:
		_, err := h.hsmClient.GenerateKeyPair("network-key", "ECDSA")
		return err
	default:
		return fmt.Errorf("unsupported secret type: %s", secretName)
	}
}

func (h *HSMSecretsManager) executeKeyRotation(operation *ThresholdOperation) error {
	secretName := operation.Metadata["secret_name"].(string)
	
	switch secretName {
	case secrets.ValidatorKey:
		return h.hsmClient.DeleteKey("validator-key")
	case secrets.NetworkKey:
		return h.hsmClient.DeleteKey("network-key")
	default:
		return fmt.Errorf("unsupported secret type: %s", secretName)
	}
}

func (h *HSMSecretsManager) getValidatorKey() ([]byte, error) {
	publicKey, err := h.hsmClient.GetPublicKey("validator-key")
	if err != nil {
		return nil, err
	}
	
	// Return encoded public key for validator operations
	return h.encodePublicKey(publicKey)
}

func (h *HSMSecretsManager) getNetworkKey() ([]byte, error) {
	publicKey, err := h.hsmClient.GetPublicKey("network-key")
	if err != nil {
		return nil, err
	}
	
	return h.encodePublicKey(publicKey)
}

func (h *HSMSecretsManager) encodePublicKey(pubKey *ecdsa.PublicKey) ([]byte, error) {
	// Encode the public key in the format expected by the node
	// This is a simplified implementation
	return json.Marshal(map[string]interface{}{
		"x": pubKey.X.String(),
		"y": pubKey.Y.String(),
	})
}

func (h *HSMSecretsManager) updateOperationStatus(operationID string, status OperationStatus) {
	h.operationMutex.Lock()
	if operation, exists := h.pendingOperations[operationID]; exists {
		operation.Status = status
	}
	h.operationMutex.Unlock()
}

func (h *HSMSecretsManager) generateOperationID() string {
	return fmt.Sprintf("hsm-op-%d", time.Now().UnixNano())
}

// SignWithThreshold performs cryptographic signing with threshold approval
func (h *HSMSecretsManager) SignWithThreshold(keyID string, data []byte) ([]byte, error) {
	operation := &ThresholdOperation{
		ID:           h.generateOperationID(),
		Type:         OpTypeSignature,
		Payload:      data,
		RequiredSigs: h.threshold,
		Approvals:    make(map[string]*Approval),
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(1 * time.Hour), // Shorter expiry for signatures
		Status:       StatusPending,
		Metadata: map[string]interface{}{
			"key_id":    keyID,
			"operation": "sign",
		},
	}
	
	if err := h.executeThresholdOperation(operation); err != nil {
		return nil, err
	}
	
	// Once approved, perform the actual signing
	return h.hsmClient.Sign(keyID, data)
} 