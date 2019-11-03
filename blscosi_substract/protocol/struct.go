package protocol

import (
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

// DefaultProtocolName can be used from other packages to refer to this protocol.
// If this name is used, then the suite used to verify signatures must be
// the default cothority.Suite.
const DefaultProtocolName = "substractCoSiDefault"

func init() {
	network.RegisterMessages(&Rumor{}, &SignatureRequest{}, &Shutdown{})
}

// Rumor is a struct that can be sent in the gossip protocol
type Rumor struct {
	Params   Parameters
	Response Response
	Map      BitMap
	Msg      []byte
}

// RumorMessage just contains a Rumor and the data necessary to identify and
// process the message in the onet framework.
type RumorMessage struct {
	*onet.TreeNode
	Rumor
}

// SignatureRequest is a struct that can be sent in the gossip protocol
type SignatureRequest struct {
	idx uint32
	Msg []byte
}

// SignatureRequestMessage contains a SignatureRequest and the data necessary to identify and
// process the message in the onet framework.
type SignatureRequestMessage struct {
	*onet.TreeNode
	SignatureRequest
}

// Shutdown is a struct that can be sent in the gossip protocol
// A valid shutdown message must contain a proof that the root has seen a valid
// final signature. This is to prevent faked shutdown messages that take down the
// gossip protocol. Thus the shutdown message contains the final signature,
// which in turn is signed by root.
type Shutdown struct {
	Params           Parameters
	FinalCoSignature BlsSignature
	RootSig          []byte
	Msg              []byte
}

// ShutdownMessage just contains a Shutdown and the data necessary to identify
// and process the message in the onet framework.
type ShutdownMessage struct {
	*onet.TreeNode
	Shutdown
}

// Response is the blscosi response message
type Response struct {
	Signature []byte
	Mask      []byte
}
