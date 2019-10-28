// Package protocol implements the BLS protocol using a main protocol and multiple
// subprotocols, one for each substree.
package protocol

import (
	"errors"
	"fmt"
	"go.dedis.ch/kyber/v3/sign/bls"
	"math/rand"
	"sync"
	"time"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/sign"
	"go.dedis.ch/kyber/v3/sign/bdn"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
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

// BlsCosiMaskAggr holds the parameters of the protocol.
// It also defines a channel that will receive the final signature.
// This protocol exists on all nodes.
type BlsCosiMaskAggr struct {
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
	RumorsChan           chan RumorMessage
	SignatureRequestChan chan SignatureRequestMessage
	ShutdownChan         chan ShutdownMessage
}

// NewDefaultProtocol is the default protocol function used for registration
// with an always-true verification.
// Called by GlobalRegisterDefaultProtocols
func NewDefaultProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	vf := func(a, b []byte) bool { return true }
	return NewBlsCosiMaskAggr(n, vf, pairing.NewSuiteBn256())
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

// NewBlsCosiMaskAggr method is used to define the blscosi protocol.
func NewBlsCosiMaskAggr(n *onet.TreeNodeInstance, vf VerificationFn, suite *pairing.SuiteBn256) (onet.ProtocolInstance, error) {
	nNodes := len(n.Roster().List)
	c := &BlsCosiMaskAggr{
		TreeNodeInstance: n,
		FinalSignature:   make(chan BlsSignature, 1),
		Timeout:          defaultTimeout,
		Threshold:        DefaultThreshold(nNodes),
		startChan:        make(chan bool, 1),
		verificationFn:   vf,
		suite:            suite,
	}

	err := c.RegisterChannels(&c.RumorsChan, &c.SignatureRequestChan, &c.ShutdownChan)
	if err != nil {
		return nil, errors.New("couldn't register channels: " + err.Error())
	}

	return c, nil
}

// Shutdown stops the protocol
func (p *BlsCosiMaskAggr) Shutdown() error {
	p.stoppedOnce.Do(func() {
		close(p.startChan)
		close(p.FinalSignature)
	})
	return nil
}

// Start is done only by root and starts the protocol.
// It also verifies that the protocol has been correctly parameterized.
func (p *BlsCosiMaskAggr) Start() error {
	err := p.checkIntegrity()
	if err != nil {
		p.Done()
		return err
	}

	log.Lvlf3("Starting BLS Mask on %v", p.ServerIdentity())
	p.startChan <- true
	return nil
}

// Dispatch is the main method of the protocol for all nodes.
func (p *BlsCosiMaskAggr) Dispatch() error {
	defer p.Done()

	protocolTimeout := time.After(shutdownAfter)

	log.Lvlf3("Gossip protocol started at node %v", p.ServerIdentity())

	var shutdownStruct Shutdown

	// When `shutdown` is true, we'll initiate a "soft shutdown": the protocol
	// stays alive here on this node, but no more rumor messages are sent.
	shutdown := false
	done := false

	var rumor *RumorMessage
	var ownId uint32
	var finalResponse *Response

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
	} else {
		select {
		case rumorMsg := <-p.RumorsChan:
			rumor = &rumorMsg
			p.Params = rumor.Params
			// Copy bytes due to the way protobuf allows the bytes to be
			// shared with the underlying buffer
			p.Msg = rumor.Msg[:]
		case shutdownMsg := <-p.ShutdownChan:
			p.Params = shutdownMsg.Params
			p.Msg = shutdownMsg.Msg[:]
			log.Lvl5("Received shutdown")
			if err := p.verifyShutdown(shutdownMsg); err == nil {
				shutdownStruct = shutdownMsg.Shutdown
				shutdown = true
			} else {
				log.Lvl1("Got first spoofed shutdown:", err)
				// Don't take any action
			}
		case <-protocolTimeout:
			shutdown = true
			done = true
		}
	}

	// responses is a map where we collect all signatures.
	allResponses := NewAllResponses(Response{}, make(BitMap), Response{}, make(BitMap), make([]*Response, 0), make([]BitMap, 0))

	// Add own signature.
	allResponses, ownId, err := p.trySign(allResponses)
	if err != nil {
		return err
	}

	if rumor != nil {
		shutdown, finalResponse, err = handleRumor(allResponses, rumor, p)
		if err != nil {
			return err
		}
	}

	ticker := time.NewTicker(p.Params.GossipTick)
	for !shutdown {
		select {
		case rumor := <-p.RumorsChan:
			shutdown, finalResponse, err = handleRumor(allResponses, &rumor, p)
			if err != nil {
				return err
			}
		case signatureRequest := <-p.SignatureRequestChan:
			shutdown, finalResponse, err = handleSignatureRequest(allResponses, &signatureRequest, p)
			if err != nil {
				return err
			}
		case shutdownMsg := <-p.ShutdownChan:
			log.Lvl5("Received shutdown")
			if err := p.verifyShutdown(shutdownMsg); err == nil {
				shutdownStruct = shutdownMsg.Shutdown
				shutdown = true
			} else {
				log.Lvl1("Got spoofed shutdown:", err)
				log.Lvl3("Length was:", len(shutdownMsg.FinalCoSignature))
				// Don't take any action
			}
		case <-ticker.C:
			log.Lvl5("Outgoing rumor")
			p.sendRumors(*allResponses, ownId)
		case <-protocolTimeout:
			shutdown = true
			done = true
		}
	}
	log.Lvl5("Done with gossiping")
	ticker.Stop()

	if p.IsRoot() {
		log.Lvl3(p.ServerIdentity().Address, "collected all signature responses")

		log.Lvlf3("%v is aggregating signatures", p.ServerIdentity())
		// generate root signature

		var sigs [][]byte
		sigs = append(sigs, finalResponse.Signature)

		// These signatures have already been multiplied with their coefficients
		// So we use the plain BLS aggregation rather than BDN
		sig, err := bls.AggregateSignatures(p.suite, sigs...)
		if err != nil {
			return err
		}

		signaturePoint := p.suite.G1().Point()
		err = signaturePoint.UnmarshalBinary(sig)
		if err != nil {
			return err
		}

		signature, err := signaturePoint.MarshalBinary()
		if err != nil {
			return err
		}

		finalMask, err := sign.NewMask(p.suite, p.Publics(), nil)
		if err != nil {
			return err
		}
		finalMask.Merge(finalResponse.Mask)

		finalSig := append(signature, finalMask.Mask()...)
		log.Lvlf3("%v created final signature %x with mask %b", p.ServerIdentity(), signature, finalMask.Mask())
		p.FinalSignature <- finalSig

		// Sign shutdown message
		rootSig, err := bdn.Sign(p.suite, p.Private(), finalSig)
		if err != nil {
			return err
		}
		shutdownStruct = Shutdown{p.Params, finalSig, rootSig, p.Msg}
	}

	p.sendShutdowns(shutdownStruct)

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

func handleRumor(allResponses *AllResponses, rumor *RumorMessage, p *BlsCosiMaskAggr) (bool, *Response, error) {
	isEnough, finalResponse, err := allResponses.Add(rumor.Rumor, p)
	if err != nil {
		return false, nil, err
	}

	log.Lvlf5("Incoming rumor, %d known, %d needed, is-root %v", len(allResponses.BuiltMap), p.Threshold, p.IsRoot())
	if p.IsRoot() && isEnough {
		// We've got enough signatures.
		return true, finalResponse, nil
	}
	requestMap, isEmpty := getRequestMapFromPeer(allResponses.BuiltMap, rumor.Rumor.AvailableMask)
	if !isEmpty {
		p.sendSignatureRequest(rumor.TreeNode, SignatureRequest{Response{
			Signature: make([]byte, 0), Mask: make([]byte, 0),
		}, requestMap})
	}

	return false, nil, nil
}

func getRequestMapFromPeer(responseBitMap BitMap, peerBitMap BitMap) (BitMap, bool) {
	requestMap := make(BitMap)
	isEmpty := true
	for index, isEnabled := range responseBitMap {
		if peerBitMap[index] && isEnabled {
			requestMap[index] = true
			isEmpty = false
		}
	}
	return requestMap, isEmpty
}

func handleSignatureRequest(allResponses *AllResponses, signatureReq *SignatureRequestMessage, p *BlsCosiMaskAggr) (bool, *Response, error) {
	if len(signatureReq.SignatureRequest.Response.Signature) == 0 {
		requested, reqBitMap := allResponses.getBestMatch(signatureReq.SignatureRequest, len(p.Publics()))
		if requested != nil {
			p.sendSignatureRequest(signatureReq.TreeNode, SignatureRequest{Response{requested.Signature, requested.Mask}, reqBitMap})
		}
	} else {
		isEnough, finalResponse, err := allResponses.Add(Rumor{
			Parameters{},
			signatureReq.SignatureRequest.Response,
			signatureReq.SignatureRequest.Mask,
			make(BitMap),
			nil,
		}, p)
		if err != nil {
			return false, nil, err
		}
		log.Lvlf5("Incoming rumor, %d known, %d needed, is-root %v", len(allResponses.BuiltMap), p.Threshold, p.IsRoot())
		if p.IsRoot() && isEnough {
			// We've got enough signatures.
			return true, finalResponse, nil
		}
	}

	return false, nil, nil
}

func (p *BlsCosiMaskAggr) trySign(allResponses *AllResponses) (*AllResponses, uint32, error) {
	if !p.verificationFn(p.Msg, p.Data) {
		log.Lvlf4("Node %v refused to sign", p.ServerIdentity())
		return allResponses, 0, nil
	}
	own, idx, err := p.makeResponse()
	if err != nil {
		return allResponses, 0, err
	}
	ownMask := make(BitMap)
	ownMask[uint32(idx)] = true

	allResponses.BuiltResponse = Response{own.Signature, own.Mask}
	allResponses.BuiltMap[uint32(idx)] = true
	allResponses.OwnSignature = Response{own.Signature, own.Mask}
	allResponses.OwnMap[uint32(idx)] = true
	allResponses.AggregatedResponses = append(allResponses.AggregatedResponses, &Response{own.Signature, own.Mask})
	auxAggMap := make(BitMap)
	auxAggMap[uint32(idx)] = true
	allResponses.AggregatedMaps = append(allResponses.AggregatedMaps, auxAggMap)
	log.Lvlf4("Node %v signed", p.ServerIdentity())
	return allResponses, uint32(idx), nil
}

// sendRumors sends a rumor message to some random peers.
func (p *BlsCosiMaskAggr) sendRumors(allResponses AllResponses, ownId uint32) {
	targets, err := p.getRandomPeers(p.Params.RumorPeers)
	if err != nil {
		log.Lvl1("Couldn't get random peers:", err)
		return
	}
	log.Lvl5("Sending rumors")
	for _, target := range targets {
		p.sendRumor(target, allResponses)
	}
}

// sendRumor sends the given signatures to a peer.
func (p *BlsCosiMaskAggr) sendRumor(target *onet.TreeNode, allResponses AllResponses) {
	p.SendTo(target, &Rumor{p.Params, allResponses.OwnSignature, allResponses.OwnMap, allResponses.BuiltMap, p.Msg})
}

// sendSignatureRequest sends a signature request message to a peer.
func (p *BlsCosiMaskAggr) sendSignatureRequest(target *onet.TreeNode, signatureRequest SignatureRequest) {
	p.SendTo(target, &signatureRequest)
}

// sendShutdowns sends a shutdown message to some random peers.
func (p *BlsCosiMaskAggr) sendShutdowns(shutdown Shutdown) {
	targets, err := p.getRandomPeers(p.Params.ShutdownPeers)
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
func (p *BlsCosiMaskAggr) sendShutdown(target *onet.TreeNode, shutdown Shutdown) {
	p.SendTo(target, &shutdown)
}

// verifyShutdown verifies the legitimacy of a shutdown message.
func (p *BlsCosiMaskAggr) verifyShutdown(msg ShutdownMessage) error {
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
func (p *BlsCosiMaskAggr) getRandomPeers(numTargets int) ([]*onet.TreeNode, error) {
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
func (p *BlsCosiMaskAggr) checkIntegrity() error {
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

// checkFailureThreshold returns true when the number of failures
// is above the threshold
func (p *BlsCosiMaskAggr) checkFailureThreshold(numFailure int) bool {
	return numFailure > len(p.Roster().List)-p.Threshold
}

// Sign the message and pack it with the mask as a response
// idx is this node's index
func (p *BlsCosiMaskAggr) makeResponse() (*Response, int, error) {
	mask, err := sign.NewMask(p.suite, p.Publics(), p.Public())
	log.Lvl2("signing with", p.Public())
	if err != nil {
		return nil, 0, err
	}

	idx := mask.IndexOfNthEnabled(0) // The only set bit is this node's
	if idx < 0 {
		return nil, 0, errors.New("Couldn't find own index")
	}

	sig, err := bdn.Sign(p.suite, p.Private(), p.Msg)
	if err != nil {
		return nil, 0, err
	}
	// Multiply signature with its coefficient immediately
	sigAdd := [][]byte{sig}
	maskAdd, err := sign.NewMask(p.suite, p.Publics(), nil)
	if err != nil {
		return nil, 0, err
	}
	maskAdd.Merge(mask.Mask())
	aggSig, err := bdn.AggregateSignatures(p.suite, sigAdd, maskAdd)
	if err != nil {
		return nil, 0, err
	}
	data, err := aggSig.MarshalBinary()
	if err != nil {
		return nil, 0, err
	}

	return &Response{
		Signature: data,
		Mask:      maskAdd.Mask(),
	}, idx, nil
}
