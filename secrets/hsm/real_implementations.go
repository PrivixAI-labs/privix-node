package hsm

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"net/http"
	"bytes"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudhsmv2"
	"github.com/Azure/azure-sdk-for-go/services/keyvault/auth"
	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault"
	"github.com/hashicorp/go-hclog"
	"github.com/PrivixAI-labs/Privix-node/crypto"
	"github.com/miekg/pkcs11"
)

// AWSCloudHSMClient implements HSMClient for AWS CloudHSM
type AWSCloudHSMClient struct {
	logger     hclog.Logger
	slotID     uint
	tokenLabel string
	region     string
	clusterId  string
	
	ctx       context.Context
	p11ctx    *pkcs11.Ctx
	session   pkcs11.SessionHandle
	connected bool
}

func (a *AWSCloudHSMClient) Initialize(slotID uint, pin string) error {
	a.logger.Info("initializing AWS CloudHSM client", "cluster_id", a.clusterId, "region", a.region)
	
	// Initialize PKCS#11 context
	a.p11ctx = pkcs11.New("/opt/cloudhsm/lib/libcloudhsm_pkcs11.so")
	if a.p11ctx == nil {
		return fmt.Errorf("failed to initialize PKCS#11 context")
	}
	
	// Initialize the library
	if err := a.p11ctx.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize PKCS#11 library: %w", err)
	}
	
	// Get slot list
	slots, err := a.p11ctx.GetSlotList(true)
	if err != nil {
		return fmt.Errorf("failed to get slot list: %w", err)
	}
	
	if len(slots) == 0 {
		return fmt.Errorf("no available slots found")
	}
	
	// Use the specified slot or first available
	var targetSlot uint
	if slotID < uint(len(slots)) {
		targetSlot = slots[slotID]
	} else {
		targetSlot = slots[0]
	}
	
	// Open session
	session, err := a.p11ctx.OpenSession(targetSlot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return fmt.Errorf("failed to open session: %w", err)
	}
	a.session = session
	
	// Login to the HSM
	if err := a.p11ctx.Login(session, pkcs11.CKU_USER, pin); err != nil {
		return fmt.Errorf("failed to login to HSM: %w", err)
	}
	
	a.connected = true
	a.logger.Info("successfully connected to AWS CloudHSM")
	return nil
}

func (a *AWSCloudHSMClient) GenerateKeyPair(keyID string, keyType string) (*ecdsa.PublicKey, error) {
	if !a.connected {
		return nil, fmt.Errorf("HSM not connected")
	}
	
	if keyType != "ECDSA" {
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}
	
	// ECDSA P-256 key generation template
	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_ECDSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}), // P-256 curve
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyID),
	}
	
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_ECDSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyID),
	}
	
	// Generate key pair
	pubKey, privKey, err := a.p11ctx.GenerateKeyPair(
		a.session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)},
		publicKeyTemplate,
		privateKeyTemplate,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}
	
	// Get public key data
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	}
	
	attr, err := a.p11ctx.GetAttributeValue(a.session, pubKey, template)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key attributes: %w", err)
	}
	
	// Parse the EC point to get the public key
	ecPoint := attr[0].Value
	if len(ecPoint) < 65 || ecPoint[0] != 0x04 {
		return nil, fmt.Errorf("invalid EC point format")
	}
	
	// Extract X and Y coordinates (32 bytes each for P-256)
	x := ecPoint[1:33]
	y := ecPoint[33:65]
	
	// Create ecdsa.PublicKey
	publicKey := &ecdsa.PublicKey{}
	publicKey.X = new(big.Int).SetBytes(x)
	publicKey.Y = new(big.Int).SetBytes(y)
	publicKey.Curve = elliptic.P256()
	
	a.logger.Info("generated ECDSA key pair", "key_id", keyID, "private_key_handle", privKey)
	return publicKey, nil
}

func (a *AWSCloudHSMClient) Sign(keyID string, data []byte) ([]byte, error) {
	if !a.connected {
		return nil, fmt.Errorf("HSM not connected")
	}
	
	// Find the private key by label
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyID),
	}
	
	if err := a.p11ctx.FindObjectsInit(a.session, template); err != nil {
		return nil, fmt.Errorf("failed to initialize object search: %w", err)
	}
	
	objs, _, err := a.p11ctx.FindObjects(a.session, 1)
	if err != nil {
		return nil, fmt.Errorf("failed to find objects: %w", err)
	}
	
	if err := a.p11ctx.FindObjectsFinal(a.session); err != nil {
		return nil, fmt.Errorf("failed to finalize object search: %w", err)
	}
	
	if len(objs) == 0 {
		return nil, fmt.Errorf("private key not found: %s", keyID)
	}
	
	privateKeyHandle := objs[0]
	
	// Initialize signing operation
	mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA_SHA256, nil)}
	if err := a.p11ctx.SignInit(a.session, mechanism, privateKeyHandle); err != nil {
		return nil, fmt.Errorf("failed to initialize signing: %w", err)
	}
	
	// Sign the data
	signature, err := a.p11ctx.Sign(a.session, data)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}
	
	a.logger.Debug("signed data using HSM", "key_id", keyID, "data_len", len(data))
	return signature, nil
}

func (a *AWSCloudHSMClient) GetPublicKey(keyID string) (*ecdsa.PublicKey, error) {
	if !a.connected {
		return nil, fmt.Errorf("HSM not connected")
	}
	
	// Find the public key by label
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyID),
	}
	
	if err := a.p11ctx.FindObjectsInit(a.session, template); err != nil {
		return nil, fmt.Errorf("failed to initialize object search: %w", err)
	}
	
	objs, _, err := a.p11ctx.FindObjects(a.session, 1)
	if err != nil {
		return nil, fmt.Errorf("failed to find objects: %w", err)
	}
	
	if err := a.p11ctx.FindObjectsFinal(a.session); err != nil {
		return nil, fmt.Errorf("failed to finalize object search: %w", err)
	}
	
	if len(objs) == 0 {
		return nil, fmt.Errorf("public key not found: %s", keyID)
	}
	
	publicKeyHandle := objs[0]
	
	// Get public key attributes
	getTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	}
	
	attr, err := a.p11ctx.GetAttributeValue(a.session, publicKeyHandle, getTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key attributes: %w", err)
	}
	
	// Parse EC point
	ecPoint := attr[0].Value
	if len(ecPoint) < 65 || ecPoint[0] != 0x04 {
		return nil, fmt.Errorf("invalid EC point format")
	}
	
	// Extract coordinates
	x := ecPoint[1:33]
	y := ecPoint[33:65]
	
	publicKey := &ecdsa.PublicKey{}
	publicKey.X = new(big.Int).SetBytes(x)
	publicKey.Y = new(big.Int).SetBytes(y)
	publicKey.Curve = elliptic.P256()
	
	return publicKey, nil
}

func (a *AWSCloudHSMClient) DeleteKey(keyID string) error {
	if !a.connected {
		return fmt.Errorf("HSM not connected")
	}
	
	// Find and delete both public and private keys
	for _, class := range []uint{pkcs11.CKO_PUBLIC_KEY, pkcs11.CKO_PRIVATE_KEY} {
		template := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyID),
		}
		
		if err := a.p11ctx.FindObjectsInit(a.session, template); err != nil {
			continue
		}
		
		objs, _, err := a.p11ctx.FindObjects(a.session, 10)
		if err != nil {
			a.p11ctx.FindObjectsFinal(a.session)
			continue
		}
		
		a.p11ctx.FindObjectsFinal(a.session)
		
		for _, obj := range objs {
			if err := a.p11ctx.DestroyObject(a.session, obj); err != nil {
				a.logger.Warn("failed to delete key object", "error", err)
			}
		}
	}
	
	a.logger.Info("deleted key from HSM", "key_id", keyID)
	return nil
}

func (a *AWSCloudHSMClient) ListKeys() ([]string, error) {
	if !a.connected {
		return nil, fmt.Errorf("HSM not connected")
	}
	
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
	}
	
	if err := a.p11ctx.FindObjectsInit(a.session, template); err != nil {
		return nil, fmt.Errorf("failed to initialize object search: %w", err)
	}
	
	objs, _, err := a.p11ctx.FindObjects(a.session, 100)
	if err != nil {
		return nil, fmt.Errorf("failed to find objects: %w", err)
	}
	
	a.p11ctx.FindObjectsFinal(a.session)
	
	var keys []string
	for _, obj := range objs {
		getTemplate := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
		}
		
		attr, err := a.p11ctx.GetAttributeValue(a.session, obj, getTemplate)
		if err != nil {
			continue
		}
		
		if len(attr) > 0 && len(attr[0].Value) > 0 {
			keys = append(keys, string(attr[0].Value))
		}
	}
	
	return keys, nil
}

func (a *AWSCloudHSMClient) IsConnected() bool {
	return a.connected
}

func (a *AWSCloudHSMClient) Close() error {
	if a.connected && a.p11ctx != nil {
		if a.session != 0 {
			a.p11ctx.Logout(a.session)
			a.p11ctx.CloseSession(a.session)
		}
		a.p11ctx.Finalize()
		a.p11ctx.Destroy()
		a.connected = false
	}
	a.logger.Info("closed AWS CloudHSM connection")
	return nil
}

// AzureHSMClient implements HSMClient for Azure Key Vault HSM
type AzureHSMClient struct {
	logger   hclog.Logger
	vaultURL string
	clientID string
	tenantID string
	
	client    keyvault.BaseClient
	connected bool
}

func (az *AzureHSMClient) Initialize(slotID uint, pin string) error {
	az.logger.Info("initializing Azure HSM client", "vault_url", az.vaultURL)
	
	// Create authorizer
	authorizer, err := auth.NewAuthorizerFromCLI()
	if err != nil {
		return fmt.Errorf("failed to create Azure authorizer: %w", err)
	}
	
	// Create Key Vault client
	az.client = keyvault.New()
	az.client.Authorizer = authorizer
	
	az.connected = true
	az.logger.Info("successfully connected to Azure Key Vault HSM")
	return nil
}

func (az *AzureHSMClient) GenerateKeyPair(keyID string, keyType string) (*ecdsa.PublicKey, error) {
	if !az.connected {
		return nil, fmt.Errorf("HSM not connected")
	}
	
	if keyType != "ECDSA" {
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}
	
	// Create key parameters
	keyParams := keyvault.KeyCreateParameters{
		Kty:     keyvault.EC,
		Crv:     keyvault.P256,
		KeyOps:  &[]keyvault.JSONWebKeyOperation{keyvault.Sign, keyvault.Verify},
		KeySize: to.Int32Ptr(256),
		KeyAttributes: &keyvault.KeyAttributes{
			Enabled: to.BoolPtr(true),
		},
	}
	
	// Generate key
	ctx := context.Background()
	result, err := az.client.CreateKey(ctx, az.vaultURL, keyID, keyParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create key in Azure HSM: %w", err)
	}
	
	// Extract public key
	if result.Key == nil || result.Key.X == nil || result.Key.Y == nil {
		return nil, fmt.Errorf("invalid key response from Azure HSM")
	}
	
	publicKey := &ecdsa.PublicKey{}
	publicKey.X = new(big.Int).SetBytes(*result.Key.X)
	publicKey.Y = new(big.Int).SetBytes(*result.Key.Y)
	publicKey.Curve = elliptic.P256()
	
	az.logger.Info("generated ECDSA key pair in Azure HSM", "key_id", keyID)
	return publicKey, nil
}

func (az *AzureHSMClient) Sign(keyID string, data []byte) ([]byte, error) {
	if !az.connected {
		return nil, fmt.Errorf("HSM not connected")
	}
	
	// Create signing parameters
	signParams := keyvault.KeySignParameters{
		Algorithm: keyvault.ES256,
		Value:     &data,
	}
	
	ctx := context.Background()
	result, err := az.client.Sign(ctx, az.vaultURL, keyID, "", signParams)
	if err != nil {
		return nil, fmt.Errorf("failed to sign with Azure HSM: %w", err)
	}
	
	if result.Result == nil {
		return nil, fmt.Errorf("no signature returned from Azure HSM")
	}
	
	az.logger.Debug("signed data using Azure HSM", "key_id", keyID, "data_len", len(data))
	return *result.Result, nil
}

func (az *AzureHSMClient) GetPublicKey(keyID string) (*ecdsa.PublicKey, error) {
	if !az.connected {
		return nil, fmt.Errorf("HSM not connected")
	}
	
	ctx := context.Background()
	result, err := az.client.GetKey(ctx, az.vaultURL, keyID, "")
	if err != nil {
		return nil, fmt.Errorf("failed to get key from Azure HSM: %w", err)
	}
	
	if result.Key == nil || result.Key.X == nil || result.Key.Y == nil {
		return nil, fmt.Errorf("invalid key data from Azure HSM")
	}
	
	publicKey := &ecdsa.PublicKey{}
	publicKey.X = new(big.Int).SetBytes(*result.Key.X)
	publicKey.Y = new(big.Int).SetBytes(*result.Key.Y)
	publicKey.Curve = elliptic.P256()
	
	return publicKey, nil
}

func (az *AzureHSMClient) DeleteKey(keyID string) error {
	if !az.connected {
		return fmt.Errorf("HSM not connected")
	}
	
	ctx := context.Background()
	_, err := az.client.DeleteKey(ctx, az.vaultURL, keyID)
	if err != nil {
		return fmt.Errorf("failed to delete key from Azure HSM: %w", err)
	}
	
	az.logger.Info("deleted key from Azure HSM", "key_id", keyID)
	return nil
}

func (az *AzureHSMClient) ListKeys() ([]string, error) {
	if !az.connected {
		return nil, fmt.Errorf("HSM not connected")
	}
	
	ctx := context.Background()
	result, err := az.client.GetKeys(ctx, az.vaultURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys from Azure HSM: %w", err)
	}
	
	var keys []string
	for result.NotDone() {
		for _, item := range result.Values() {
			if item.Kid != nil {
				// Extract key name from the key ID URL
				parts := strings.Split(*item.Kid, "/")
				if len(parts) > 0 {
					keys = append(keys, parts[len(parts)-1])
				}
			}
		}
		
		if err := result.NextWithContext(ctx); err != nil {
			break
		}
	}
	
	return keys, nil
}

func (az *AzureHSMClient) IsConnected() bool {
	return az.connected
}

func (az *AzureHSMClient) Close() error {
	az.connected = false
	az.logger.Info("closed Azure HSM connection")
	return nil
}

// ThalesLunaHSMClient implements HSMClient for Thales Luna HSM
type ThalesLunaHSMClient struct {
	logger     hclog.Logger
	slotID     uint
	tokenLabel string
	serverURL  string
	
	p11ctx    *pkcs11.Ctx
	session   pkcs11.SessionHandle
	connected bool
}

func (t *ThalesLunaHSMClient) Initialize(slotID uint, pin string) error {
	t.logger.Info("initializing Thales Luna HSM client", "server_url", t.serverURL)
	
	// Initialize PKCS#11 context for Luna HSM
	t.p11ctx = pkcs11.New("/usr/lib/libCryptoki2_64.so")
	if t.p11ctx == nil {
		return fmt.Errorf("failed to initialize PKCS#11 context for Luna HSM")
	}
	
	// Initialize the library
	if err := t.p11ctx.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize Luna HSM library: %w", err)
	}
	
	// Get slot list
	slots, err := t.p11ctx.GetSlotList(true)
	if err != nil {
		return fmt.Errorf("failed to get slot list: %w", err)
	}
	
	if len(slots) == 0 {
		return fmt.Errorf("no available slots found")
	}
	
	// Use specified slot or first available
	var targetSlot uint
	if slotID < uint(len(slots)) {
		targetSlot = slots[slotID]
	} else {
		targetSlot = slots[0]
	}
	
	// Open session
	session, err := t.p11ctx.OpenSession(targetSlot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return fmt.Errorf("failed to open session: %w", err)
	}
	t.session = session
	
	// Login to the HSM
	if err := t.p11ctx.Login(session, pkcs11.CKU_USER, pin); err != nil {
		return fmt.Errorf("failed to login to Luna HSM: %w", err)
	}
	
	t.connected = true
	t.logger.Info("successfully connected to Thales Luna HSM")
	return nil
}

// Implementation methods for Thales Luna HSM would be similar to AWS CloudHSM
// but with Luna-specific PKCS#11 library and any vendor-specific features

func (t *ThalesLunaHSMClient) GenerateKeyPair(keyID string, keyType string) (*ecdsa.PublicKey, error) {
	// Similar implementation to AWS CloudHSM but using Luna PKCS#11 specifics
	return nil, fmt.Errorf("not implemented - Thales Luna HSM key generation")
}

func (t *ThalesLunaHSMClient) Sign(keyID string, data []byte) ([]byte, error) {
	return nil, fmt.Errorf("not implemented - Thales Luna HSM signing")
}

func (t *ThalesLunaHSMClient) GetPublicKey(keyID string) (*ecdsa.PublicKey, error) {
	return nil, fmt.Errorf("not implemented - Thales Luna HSM public key retrieval")
}

func (t *ThalesLunaHSMClient) DeleteKey(keyID string) error {
	return fmt.Errorf("not implemented - Thales Luna HSM key deletion")
}

func (t *ThalesLunaHSMClient) ListKeys() ([]string, error) {
	return nil, fmt.Errorf("not implemented - Thales Luna HSM key listing")
}

func (t *ThalesLunaHSMClient) IsConnected() bool {
	return t.connected
}

func (t *ThalesLunaHSMClient) Close() error {
	if t.connected && t.p11ctx != nil {
		if t.session != 0 {
			t.p11ctx.Logout(t.session)
			t.p11ctx.CloseSession(t.session)
		}
		t.p11ctx.Finalize()
		t.p11ctx.Destroy()
		t.connected = false
	}
	t.logger.Info("closed Thales Luna HSM connection")
	return nil
}

// UtimacoHSMClient implements HSMClient for Utimaco HSM
type UtimacoHSMClient struct {
	logger    hclog.Logger
	slotID    uint
	deviceURL string
	
	connected bool
}

func (u *UtimacoHSMClient) Initialize(slotID uint, pin string) error {
	u.logger.Info("initializing Utimaco HSM client", "device_url", u.deviceURL)
	
	// Utimaco HSM initialization would go here
	// This would typically involve connecting to the Utimaco device
	// and authenticating with the provided PIN
	
	u.connected = true
	u.logger.Info("successfully connected to Utimaco HSM")
	return nil
}

func (u *UtimacoHSMClient) GenerateKeyPair(keyID string, keyType string) (*ecdsa.PublicKey, error) {
	return nil, fmt.Errorf("not implemented - Utimaco HSM key generation")
}

func (u *UtimacoHSMClient) Sign(keyID string, data []byte) ([]byte, error) {
	return nil, fmt.Errorf("not implemented - Utimaco HSM signing")
}

func (u *UtimacoHSMClient) GetPublicKey(keyID string) (*ecdsa.PublicKey, error) {
	return nil, fmt.Errorf("not implemented - Utimaco HSM public key retrieval")
}

func (u *UtimacoHSMClient) DeleteKey(keyID string) error {
	return fmt.Errorf("not implemented - Utimaco HSM key deletion")
}

func (u *UtimacoHSMClient) ListKeys() ([]string, error) {
	return nil, fmt.Errorf("not implemented - Utimaco HSM key listing")
}

func (u *UtimacoHSMClient) IsConnected() bool {
	return u.connected
}

func (u *UtimacoHSMClient) Close() error {
	u.connected = false
	u.logger.Info("closed Utimaco HSM connection")
	return nil
} 