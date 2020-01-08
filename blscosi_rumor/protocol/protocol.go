// Package protocol implements the BLS protocol using a main protocol and multiple
// subprotocols, one for each substree.
package protocol

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/sign"
	"go.dedis.ch/onet/v4"
	"go.dedis.ch/onet/v4/log"
	"go.dedis.ch/onet/v4/network"
)

const defaultTimeout = 10 * time.Second
const shutdownAfter = 11 * time.Second // finally truly shutdown the protocol

// VerificationFn is called on every node. Where msg is the message that is
// co-signed and the data is additional data for verification.
type VerificationFn func(msg, data []byte) bool

// init is done at startup. It defines every messages that is handled by the network
// and registers the protocols.
func init() {
	GlobalRegisterDefaultProtocols()
}

// BlsCosi holds the parameters of the protocol.
// It also defines a channel that will receive the final signature.
// This protocol exists on all nodes.
type BlsCosi struct {
	*onet.TreeNodeInstance
	Msg  []byte
	Data []byte
	// Timeout is not a global timeout for the protocol, but a timeout used
	// for waiting for responses.
	Timeout        time.Duration
	Threshold      int
	FinalSignature chan BlsSignature // final signature that is sent back to client

	stoppedOnce    sync.Once
	startChan      chan bool
	verificationFn VerificationFn
	suite          *pairing.SuiteBn256
	Params         Parameters // mainly for simulations
}

// NewDefaultProtocol is the default protocol function used for registration
// with an always-true verification.
// Called by GlobalRegisterDefaultProtocols
func NewDefaultProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	vf := func(a, b []byte) bool { return true }
	return NewBlsCosi(n, vf, pairing.NewSuiteBn256())
}

// GlobalRegisterDefaultProtocols is used to register the protocols before use,
// most likely in an init function.
func GlobalRegisterDefaultProtocols() {
	onet.GlobalProtocolRegister(DefaultProtocolName, NewDefaultProtocol)
}

// DefaultThreshold computes the minimal threshold authorized using
// the formula 3f+1
func DefaultThreshold(n int) int {
	f := (n - 1) / 3
	return n - f
}

// NewBlsCosi method is used to define the blscosi protocol.
func NewBlsCosi(n *onet.TreeNodeInstance, vf VerificationFn, suite *pairing.SuiteBn256) (onet.ProtocolInstance, error) {
	nNodes := len(n.Roster().List)
	c := &BlsCosi{
		TreeNodeInstance: n,
		FinalSignature:   make(chan BlsSignature, 1),
		Timeout:          defaultTimeout,
		Threshold:        DefaultThreshold(nNodes),
		startChan:        make(chan bool, 1),
		verificationFn:   vf,
		suite:            suite,
	}

	return c, nil
}

// Start is done only by root and starts the protocol.
// It also verifies that the protocol has been correctly parameterized.
func (p *BlsCosi) Start() error {
	err := p.checkIntegrity()
	if err != nil {
		p.Done()
		return err
	}

	log.Lvlf3("Starting BLS CoSi on %v", p.ServerIdentity())
	p.startChan <- true
	return nil
}

// Dispatch is the main method of the protocol for all nodes.
func (p *BlsCosi) Dispatch() error {
	defer p.Done()

	protocolTimeout := time.After(shutdownAfter)

	log.Lvlf3("Gossip protocol started at node %v", p.ServerIdentity())

	// When `shutdown` is true, we'll initiate a "soft shutdown": the protocol
	// stays alive here on this node, but no more rumor messages are sent.
	shutdown := false

	responses := make(SimpleResponses)

	// The root must wait for Start() to have been called.
	if p.IsRoot() {
		select {
		case _, ok := <-p.startChan:
			if !ok {
				return errors.New("protocol finished prematurely")
			}
		case <-time.After(time.Second):
			return errors.New("timeout, did you forget to call Start?")
		}

		ticker := time.NewTicker(p.Params.GossipTick)
		receivedSignatures := make(map[network.ServerIdentityID][]byte)
		pendingRoster := onet.Roster{}
		pendingRoster.List = make([]*network.ServerIdentity, 0)
		rumorId := -1
		var err error
		completeList := p.TreeNodeInstance.List()
		for _, treeNode := range completeList {
			pendingRoster.List = append(pendingRoster.List, treeNode.ServerIdentity)
		}

		for !shutdown {
			select {
			case <-ticker.C:
				if rumorId != -1 {
					// Update received signatures
					if len(receivedSignatures) != len(p.GetOverlay().RumorsSent[rumorId].Acknowledgements) {
						for key, signature := range p.GetOverlay().RumorsSent[rumorId].Acknowledgements {
							if _, ok := receivedSignatures[key]; !ok {
								receivedSignatures[key] = signature
								rosterIndex := -1
								for i, identity := range pendingRoster.List {
									if identity.ID.Equal(key) {
										rosterIndex = i
										break
									}
								}
								if rosterIndex != -1 {
									pendingRoster.List = append(pendingRoster.List[:rosterIndex], pendingRoster.List[rosterIndex+1:]...)
								}
							}
						}
					}
				}
				if len(receivedSignatures) >= p.Threshold {
					mapIdToIndex := make(map[network.ServerIdentityID]int)
					iaux := 0
					for _, tree := range completeList {
						mapIdToIndex[tree.ServerIdentity.ID] = iaux
						iaux = iaux + 1
					}
					for key, element := range receivedSignatures {
						auxMask, err := sign.NewMask(p.suite, p.Publics(), nil)
						if err != nil {
							return err
						}
						auxMask.SetBit(mapIdToIndex[key], true)
						err = responses.Add(mapIdToIndex[key], &Response{
							Signature: element,
							Mask:      auxMask.Mask(),
						})
						if err != nil {
							return err
						}
					}
					shutdown = true
				} else {
					rumorId, err = p.GetOverlay().SendRumor(pendingRoster, 3, p.Msg, p.Params.GossipTick, rumorId)
					if err != nil {
						log.Lvl2("Failed to SendRumor on tick")
						return err
					}
				}
			case <-protocolTimeout:
				log.Lvl5("Timed out of protocol")
				shutdown = true
			}
		}

		log.Lvl3(p.ServerIdentity().Address, "collected all signature responses")

		log.Lvlf3("%v is aggregating signatures", p.ServerIdentity())
		// generate root signature
		signaturePoint, finalMask, err := responses.Aggregate(p.suite, p.Publics())
		if err != nil {
			return err
		}

		signature, err := signaturePoint.MarshalBinary()
		if err != nil {
			return err
		}

		finalSig := append(signature, finalMask.Mask()...)
		log.Lvlf3("%v created final signature %x with mask %b", p.ServerIdentity(), signature, finalMask.Mask())
		p.FinalSignature <- finalSig
	}

	log.Lvl5("Done with the whole protocol")

	return nil
}

// checkIntegrity checks if the protocol has been instantiated with
// correct parameters
func (p *BlsCosi) checkIntegrity() error {
	if p.Msg == nil {
		return fmt.Errorf("no proposal msg specified")
	}
	if p.CreateProtocol == nil {
		return fmt.Errorf("no create protocol function specified")
	}
	if p.verificationFn == nil {
		return fmt.Errorf("verification function cannot be nil")
	}
	if p.Timeout < 500*time.Microsecond {
		return fmt.Errorf("unrealistic timeout")
	}
	if p.Threshold > p.Tree().Size() {
		return fmt.Errorf("threshold (%d) bigger than number of nodes (%d)", p.Threshold, p.Tree().Size())
	}
	if p.Threshold < 1 {
		return fmt.Errorf("threshold of %d smaller than one node", p.Threshold)
	}

	return nil
}
