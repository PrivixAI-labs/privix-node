package authtoken

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/spf13/cobra"
)

var (
	params = &authtokenParams{}
)

type authtokenParams struct {
	secret string
}

func GetCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "authtoken",
		Short: "Generates a SHA256 authentication token. Uses a random seed if --secret is not provided.",
		RunE:  run,
	}

	cmd.Flags().StringVar(
		&params.secret,
		"secret",
		"",
		"the secret to generate the token from. If empty, a random secret is generated",
	)

	return cmd
}

func run(cmd *cobra.Command, _ []string) error {
	var input []byte
	var err error

	if params.secret != "" {
		input = []byte(params.secret)
	} else {
		randomBytes := make([]byte, 32)
		_, err = rand.Read(randomBytes)
		if err != nil {
			return fmt.Errorf("failed to generate random bytes: %w", err)
		}
		input = randomBytes
	}

	hash := sha256.Sum256(input)
	token := hex.EncodeToString(hash[:])

	fmt.Println(token)

	return nil
}
