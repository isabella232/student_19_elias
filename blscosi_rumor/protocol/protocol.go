// Package protocol implements the BLS protocol using a main protocol and multiple
// subprotocols, one for each substree.
package protocol

import (
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/sign"
	"go.dedis.ch/kyber/v3/sign/bdn"
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

	// internodes channels
	RumorsChan   chan RumorMessage
	ShutdownChan chan ShutdownMessage
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

	err := c.RegisterChannels(&c.RumorsChan, &c.ShutdownChan)
	if err != nil {
		return nil, errors.New("couldn't register channels: " + err.Error())
	}

	return c, nil
}

// Shutdown stops the protocol
func (p *BlsCosi) Shutdown() error {
	p.stoppedOnce.Do(func() {
		close(p.startChan)
		close(p.FinalSignature)
	})
	return nil
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

	var shutdownStruct Shutdown

	// When `shutdown` is true, we'll initiate a "soft shutdown": the protocol
	// stays alive here on this node, but no more rumor messages are sent.
	shutdown := false
	done := false

	// TODO use responses struct when signatures are enabled
	//responses := make(SimpleResponses)

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
	}

	if p.IsRoot() {
		ticker := time.NewTicker(p.Params.GossipTick)
		receivedSignatures := make(SignaturesMap)
		identityToSignatureMap := p.createSignaturesMap()
		pendingRoster := onet.Roster{}
		pendingRoster.List = make([]*network.ServerIdentity, 0)
		mapIdentityReceived := make(map[network.ServerIdentityID]bool)
		rumorId := -1
		var err error
		for _, treeNode := range p.TreeNodeInstance.List() {
			mapIdentityReceived[treeNode.ServerIdentity.ID] = false
			pendingRoster.List = append(pendingRoster.List, treeNode.ServerIdentity)
		}

		for !shutdown {
			select {
			case rumorMsg := <-p.RumorsChan:
				p.Msg = rumorMsg.Msg[:]
				rumorId, err = p.GetOverlay().SendRumor(pendingRoster, 3, p.Msg, p.Params.GossipTick, rumorId)
				if err != nil {
					log.Lvl2("Failed to SendRumor on rumor start")
					return err
				}
			case <-ticker.C:
				if rumorId != -1 {
					// Update received signatures
					if len(receivedSignatures) != len(p.GetOverlay().RumorsSent[rumorId].Acknowledgements) {
						for key := range p.GetOverlay().RumorsSent[rumorId].Acknowledgements {
							if !mapIdentityReceived[key] {
								receivedSignatures[key] = identityToSignatureMap[key]
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
								mapIdentityReceived[key] = true
							}
						}
					}
				}
				if len(receivedSignatures) >= p.Threshold {
					// TODO enable message signing
					//for index, tree := range p.TreeNodeInstance.List() {
					//	if privKey, ok := receivedSignatures[tree.ServerIdentity.ID]; ok {
					//		sign, err := p.makeResponseWithKey(tree.ServerIdentity.Public, privKey, index)
					//		if err != nil {
					//			return err
					//		}
					//		responses.Add(index, sign)
					//	}
					//}
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
				done = true
			}
		}
	} else {
		for !shutdown {
			select {
			case shutdownMsg := <-p.ShutdownChan:
				log.Lvl5("Received shutdown")
				p.Msg = shutdownMsg.Shutdown.Msg
				shutdown = true
				// TODO enable signature verification when signatures are enabled
				//if err := p.verifyShutdown(shutdownMsg); err == nil {
				//	shutdownStruct = shutdownMsg.Shutdown
				//	shutdown = true
				//} else {
				//	log.Lvl1("Got spoofed shutdown:", err)
				//	log.Lvl3("Length was:", len(shutdownMsg.FinalCoSignature))
				//	// Don't take any action
				//}
			case <-protocolTimeout:
				shutdown = true
				done = true
			}
		}
	}

	if p.IsRoot() {
		shutdownStruct = Shutdown{p.Params, nil, nil, p.Msg}
		done = true
		// TODO enable agg signature
		//log.Lvl3(p.ServerIdentity().Address, "collected all signature responses")
		//
		//log.Lvlf3("%v is aggregating signatures", p.ServerIdentity())
		//// generate root signature
		//signaturePoint, finalMask, err := responses.Aggregate(p.suite, p.Publics())
		//if err != nil {
		//	return err
		//}
		//
		//signature, err := signaturePoint.MarshalBinary()
		//if err != nil {
		//	return err
		//}
		//
		//finalSig := append(signature, finalMask.Mask()...)
		//log.Lvlf3("%v created final signature %x with mask %b", p.ServerIdentity(), signature, finalMask.Mask())
		//p.FinalSignature <- finalSig
		//
		//// Sign shutdown message
		//rootSig, err := bdn.Sign(p.suite, p.Private(), finalSig)
		//if err != nil {
		//	return err
		//}
		//shutdownStruct = Shutdown{p.Params, finalSig, rootSig, p.Msg}
	}

	//p.sendShutdowns(shutdownStruct)

	// We respond to every non-shutdown message with a shutdown message, to
	// ensure that all nodes will shut down eventually. This is also the reason
	// why we don't immediately do a hard shutdown.
	for !done {
		select {
		case rumor := <-p.RumorsChan:
			sender := rumor.TreeNode
			log.Lvl5("Responding to rumor with shutdown", sender.Equal(p.TreeNode()))
			p.sendShutdown(sender, shutdownStruct)
		case <-p.ShutdownChan:
			// ignore
		case <-protocolTimeout:
			done = true
		}
	}
	log.Lvl5("Done with the whole protocol")

	return nil
}

// sendShutdowns sends a shutdown message to some random peers.
func (p *BlsCosi) sendShutdowns(shutdown Shutdown) {
	targets, err := p.getRandomPeers(5)
	if err != nil {
		log.Lvl1("Couldn't get random peers for shutdown:", err)
		return
	}
	log.Lvl5("Sending shutdowns")
	for _, target := range targets {
		p.sendShutdown(target, shutdown)
	}
}

// sendShutdown sends a shutdown message to a single peer.
func (p *BlsCosi) sendShutdown(target *onet.TreeNode, shutdown Shutdown) {
	p.SendTo(target, &shutdown)
}

// verifyShutdown verifies the legitimacy of a shutdown message.
func (p *BlsCosi) verifyShutdown(msg ShutdownMessage) error {
	if len(p.Publics()) == 0 {
		return errors.New("Roster is empty")
	}
	rootPublic := p.Publics()[0]
	finalSig := msg.FinalCoSignature

	// verify final signature
	err := msg.FinalCoSignature.VerifyAggregate(p.suite, p.Msg, p.Publics())
	if err != nil {
		return err
	}

	// verify root signature of final signature
	return verify(p.suite, msg.RootSig, finalSig, rootPublic)
}

// verify checks the signature over the message with a single key
func verify(suite pairing.Suite, sig []byte, msg []byte, public kyber.Point) error {
	if len(msg) == 0 {
		return errors.New("no message provided to Verify()")
	}
	if len(sig) == 0 {
		return errors.New("no signature provided to Verify()")
	}
	err := bdn.Verify(suite, public, msg, sig)
	if err != nil {
		return fmt.Errorf("didn't get a valid signature: %s", err)
	}
	return nil
}

// getRandomPeers returns a slice of random peers (not including self).
func (p *BlsCosi) getRandomPeers(numTargets int) ([]*onet.TreeNode, error) {
	self := p.TreeNode()
	root := p.Root()
	allNodes := append(root.Children, root)

	numPeers := len(allNodes) - 1

	selfIndex := len(allNodes)
	for i, node := range allNodes {
		if node.Equal(self) {
			selfIndex = i
			break
		}
	}
	if selfIndex == len(allNodes) {
		log.Lvl1("couldn't find outselves in the roster")
		numPeers++
	}

	if numPeers < numTargets {
		return nil, errors.New("not enough nodes in the roster")
	}

	arr := make([]int, numPeers)
	for i := range arr {
		arr[i] = i
	}
	rand.Shuffle(len(arr), func(i, j int) { arr[i], arr[j] = arr[j], arr[i] })

	results := make([]*onet.TreeNode, numTargets)
	for i := range results {
		index := arr[i]
		if index >= selfIndex {
			index++
		}
		results[i] = allNodes[index]
	}
	return results, nil
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

// Sign the message and pack it with the mask as a response given a public and private key
func (p *BlsCosi) makeResponseWithKey(publicKey kyber.Point, privateKey kyber.Scalar, idx int) (*Response, error) {
	mask, err := sign.NewMask(p.suite, p.Publics(), publicKey)
	log.Lvl2("signing with", publicKey)
	if err != nil {
		return nil, err
	}

	sig, err := bdn.Sign(p.suite, privateKey, p.Msg)
	if err != nil {
		return nil, err
	}

	return &Response{
		Mask:      mask.Mask(),
		Signature: sig,
	}, nil
}

func (p *BlsCosi) createSignaturesMap() SignaturesMap {
	// TODO find way to get private signature
	//log.Lvl1(p.Private())
	//log.Lvl1(p.Root().ServerIdentity.GetPrivate())
	//log.Lvl1(p.Tree().List()[0].ServerIdentity.GetPrivate())
	//log.Lvl1(p.Roster().List[0].GetPrivate())
	//log.Lvl1(p.ServerIdentity().GetPrivate())
	newSignaturesMap := make(SignaturesMap)
	for _, node := range p.TreeNodeInstance.List() {
		newSignaturesMap[node.ServerIdentity.ID] = node.ServerIdentity.GetPrivate()
	}
	return newSignaturesMap
}
