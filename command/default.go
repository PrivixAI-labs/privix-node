package command

import (
	"encoding/binary"
	"math/rand"

	"github.com/umbracle/ethgo"

	"github.com/PrivixAI-labs/Privix-node/chain"
	"github.com/PrivixAI-labs/Privix-node/server"
)

const (
	DefaultGenesisFileName = "genesis.json"
	DefaultChainName       = "neth-smart-chain"
	DefaultBlockTime       = 3000000000
	// DefaultChainID          = 9996

	DefaultConsensus        = server.IBFTConsensus
	DefaultGenesisGasUsed   = 458752  // 0x70000
	DefaultGenesisGasLimit  = 5242880 // 0x500000
	DefaultGenesisBaseFeeEM = chain.GenesisBaseFeeEM
)

// Generate a new random ChainID for each execution
func NewChainID() uint64 {
	var b [8]byte
	_, err := rand.Read(b[:])
	if err != nil {
		panic("failed to generate secure random chain ID: " + err.Error())
	}
	return binary.LittleEndian.Uint64(b[:])
}

var DefaultChainID = NewChainID()

var (
	DefaultStake          = ethgo.Ether(1e6)
	DefaultPremineBalance = ethgo.Ether(1e6)
	DefaultGenesisBaseFee = chain.GenesisBaseFee
)

const (
	JSONOutputFlag  = "json"
	GRPCAddressFlag = "grpc-address"
	JSONRPCFlag     = "jsonrpc"
)

// GRPCAddressFlagLEGACY Legacy flag that needs to be present to preserve backwards
// compatibility with running clients
const (
	GRPCAddressFlagLEGACY = "grpc"
)
