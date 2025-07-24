package local

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/hashicorp/go-hclog"
	"github.com/PrivixAI-labs/Privix-node/helper/common"
	"github.com/PrivixAI-labs/Privix-node/secrets"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/term"
)

// LocalSecretsManager is a SecretsManager that
// stores secrets locally on disk
type LocalSecretsManager struct {
	// Logger object
	logger hclog.Logger

	// Path to the base working directory
	path string

	// Map of known secrets and their paths
	secretPathMap map[string]string

	// Mux for the secretPathMap
	secretPathMapLock sync.RWMutex

	passphrase      []byte
	passphraseErr   error
	passphraseOnce  sync.Once
}

// SecretsManagerFactory implements the factory method
func SecretsManagerFactory(
	_ *secrets.SecretsManagerConfig,
	params *secrets.SecretsManagerParams,
) (secrets.SecretsManager, error) {
	// Set up the base object
	localManager := &LocalSecretsManager{
		logger:        params.Logger.Named(string(secrets.Local)),
		secretPathMap: make(map[string]string),
	}

	// Grab the path to the working directory
	path, ok := params.Extra[secrets.Path]
	if !ok {
		return nil, errors.New("no path specified for local secrets manager")
	}

	localManager.path, ok = path.(string)
	if !ok {
		return nil, errors.New("invalid type assertion")
	}

	// Run the initial setup
	if err := localManager.Setup(); err != nil {
		return nil, fmt.Errorf("failed to setup local secrets manager: %w", err)
	}

	return localManager, nil
}

// Setup sets up the local SecretsManager
func (l *LocalSecretsManager) Setup() error {
	// The local SecretsManager initially handles only the
	// validator and networking private keys
	l.secretPathMapLock.Lock()
	defer l.secretPathMapLock.Unlock()

	subDirectories := []string{secrets.ConsensusFolderLocal, secrets.NetworkFolderLocal}

	// Set up the local directories
	if err := common.SetupDataDir(l.path, subDirectories, 0700); err != nil {
		return err
	}

	// baseDir/consensus/validator.key
	l.secretPathMap[secrets.ValidatorKey] = filepath.Join(
		l.path,
		secrets.ConsensusFolderLocal,
		secrets.ValidatorKeyLocal,
	)

	// baseDir/consensus/validator-bls.key
	l.secretPathMap[secrets.ValidatorBLSKey] = filepath.Join(
		l.path,
		secrets.ConsensusFolderLocal,
		secrets.ValidatorBLSKeyLocal,
	)

	// baseDir/libp2p/libp2p.key
	l.secretPathMap[secrets.NetworkKey] = filepath.Join(
		l.path,
		secrets.NetworkFolderLocal,
		secrets.NetworkKeyLocal,
	)

	return nil
}

// GetSecret gets the local SecretsManager's secret from disk
func (l *LocalSecretsManager) GetSecret(name string) ([]byte, error) {
	l.secretPathMapLock.RLock()
	secretPath, ok := l.secretPathMap[name]
	l.secretPathMapLock.RUnlock()

	if !ok {
		return nil, secrets.ErrSecretNotFound
	}

	// Read the encrypted secret from disk
	encryptedSecret, err := os.ReadFile(secretPath)
	if err != nil {
		return nil, fmt.Errorf(
			"unable to read secret from disk (%s), %w",
			secretPath,
			err,
		)
	}

	passphrase, err := l.getReadPassphrase()
	if err != nil {
		return nil, err
	}

	return decrypt(encryptedSecret, passphrase)
}

// SetSecret saves the local SecretsManager's secret to disk
func (l *LocalSecretsManager) SetSecret(name string, value []byte) error {
	// If the data directory is not specified, skip write
	if l.path == "" {
		return nil
	}

	l.secretPathMapLock.Lock()
	secretPath, ok := l.secretPathMap[name]
	l.secretPathMapLock.Unlock()

	if !ok {
		return secrets.ErrSecretNotFound
	}

	// Checks for existing secret
	if _, err := os.Stat(secretPath); err == nil {
		return fmt.Errorf(
			"%s already initialized",
			secretPath,
		)
	}

	passphrase, err := l.getWritePassphrase()
	if err != nil {
		return err
	}

	encryptedValue, err := encrypt(value, passphrase)
	if err != nil {
		return err
	}

	// Write the secret to disk
	if err := common.SaveFileSafe(secretPath, encryptedValue, 0600); err != nil {
		return fmt.Errorf(
			"unable to write secret to disk (%s), %w",
			secretPath,
			err,
		)
	}

	return nil
}

// HasSecret checks if the secret is present on disk
func (l *LocalSecretsManager) HasSecret(name string) bool {
	l.secretPathMapLock.RLock()
	secretPath, ok := l.secretPathMap[name]
	l.secretPathMapLock.RUnlock()

	if !ok {
		return false
	}

	_, err := os.Stat(secretPath)

	return err == nil
}

// RemoveSecret removes the local SecretsManager's secret from disk
func (l *LocalSecretsManager) RemoveSecret(name string) error {
	l.secretPathMapLock.Lock()
	secretPath, ok := l.secretPathMap[name]
	defer l.secretPathMapLock.Unlock()

	if !ok {
		return secrets.ErrSecretNotFound
	}

	delete(l.secretPathMap, name)

	if removeErr := os.Remove(secretPath); removeErr != nil {
		return fmt.Errorf("unable to remove secret, %w", removeErr)
	}

	return nil
}

func (l *LocalSecretsManager) getReadPassphrase() ([]byte, error) {
	l.passphraseOnce.Do(func() {
		fmt.Print("Enter passphrase: ")
		pass, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			l.passphraseErr = err
			return
		}
		l.passphrase = pass
	})
	return l.passphrase, l.passphraseErr
}

func (l *LocalSecretsManager) getWritePassphrase() ([]byte, error) {
	l.passphraseOnce.Do(func() {
		fmt.Print("Enter passphrase: ")
		pass, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			l.passphraseErr = err
			return
		}

		fmt.Print("Confirm passphrase: ")
		confirmation, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			l.passphraseErr = err
			return
		}
		if !bytes.Equal(pass, confirmation) {
			l.passphraseErr = errors.New("passphrases do not match")
			return
		}
		l.passphrase = pass
	})
	return l.passphrase, l.passphraseErr
}

func encrypt(data, passphrase []byte) ([]byte, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	key, err := scrypt.Key(passphrase, salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return append(salt, ciphertext...), nil
}

func decrypt(data, passphrase []byte) ([]byte, error) {
	if len(data) < 64 {
		return nil, errors.New("invalid encrypted data")
	}
	salt, encryptedData := data[:32], data[32:]

	key, err := scrypt.Key(passphrase, salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce, ciphertext := encryptedData[:gcm.NonceSize()], encryptedData[gcm.NonceSize():]

	return gcm.Open(nil, nonce, ciphertext, nil)
}