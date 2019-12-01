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

// BlsCosiSubstract holds the parameters of the protocol.
// It also defines a channel that will receive the final signature.
// This protocol exists on all nodes.
type BlsCosiSubstract struct {
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
	return NewBlsCosiSubstract(n, vf, pairing.NewSuiteBn256())
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

// NewBlsCosiSubstract method is used to define the blscosi protocol.
func NewBlsCosiSubstract(n *onet.TreeNodeInstance, vf VerificationFn, suite *pairing.SuiteBn256) (onet.ProtocolInstance, error) {
	nNodes := len(n.Roster().List)
	c := &BlsCosiSubstract{
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
func (p *BlsCosiSubstract) Shutdown() error {
	p.stoppedOnce.Do(func() {
		close(p.startChan)
		close(p.FinalSignature)
	})
	return nil
}

// Start is done only by root and starts the protocol.
// It also verifies that the protocol has been correctly parameterized.
func (p *BlsCosiSubstract) Start() error {
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
func (p *BlsCosiSubstract) Dispatch() error {
	//defer func() {
	//	if r := recover(); r != nil {
	//		fmt.Printf("MyErrorIsHere: %v\n", string(debug.Stack()))
	//	}
	//}()
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
			log.Lvl5("%v Received shutdown", ownId)
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

	// responses is where we collect all signatures.
	allResponses := NewAllResponses(make(ResponsesMap), make(BitMap), Response{make([]byte, 0), make([]byte, 0)}, make(BitMap), make([]PullResponse, 0))

	// Add own signature.
	allResponses, ownId, err := p.trySign(allResponses)
	if err != nil {
		return err
	}

	if rumor != nil {
		log.Lvlf5("Rumor received by %d, %d known, %d needed, current: %v, arrived: %v", ownId, len(allResponses.finalMap), p.Threshold, allResponses.finalMap, rumor.Rumor.Map)
		shutdown, err = handleRumor(allResponses, rumor, p)
		if err != nil {
			return err
		}
	}

	ticker := time.NewTicker(p.Params.GossipTick)
	for !shutdown {
		select {
		case rumor := <-p.RumorsChan:
			log.Lvlf5("Rumor received by %d, %d known, %d needed, current: %v, arrived: %v", ownId, len(allResponses.finalMap), p.Threshold, allResponses.finalMap, rumor.Rumor.Map)
			shutdown, err = handleRumor(allResponses, &rumor, p)

			if err != nil {
				return err
			}
		case signatureRequest := <-p.SignatureRequestChan:
			handleSignatureRequest(allResponses, ownId, &signatureRequest, p)
		case shutdownMsg := <-p.ShutdownChan:
			log.Lvlf5("%v Received shutdown from %v", ownId, shutdownMsg.RosterIndex)
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
	log.Lvlf3("%v Done with gossiping %v found", ownId, allResponses.finalMap)
	ticker.Stop()

	if p.IsRoot() {
		log.Lvl3(p.ServerIdentity().Address, "collected all signature responses")

		log.Lvlf3("%v is aggregating signatures", p.ServerIdentity())
		//var sigs [][]byte
		//sigs = append(sigs, allResponses.finalResponse.Signature)
		//
		//// These signatures have already been multiplied with their coefficients
		//// So we use the plain BLS aggregation rather than BDN
		//sig, err := bls.AggregateSignatures(p.suite, sigs...)
		//if err != nil {
		//	return err
		//}
		//
		//signaturePoint := p.suite.G1().Point()
		//err = signaturePoint.UnmarshalBinary(sig)
		//if err != nil {
		//	return err
		//}
		//
		//signature, err := signaturePoint.MarshalBinary()
		//if err != nil {
		//	return err
		//}
		//
		//finalMask, err := sign.NewMask(p.suite, p.Publics(), nil)
		//if err != nil {
		//	return err
		//}
		//finalMask.Merge(allResponses.finalResponse.Mask)

		// Other attempt
		//var sigs [][]byte
		//finalMask, err := sign.NewMask(p.suite, p.Publics(), nil)
		//
		//log.Lvlf3("aggregating total of %d signatures", finalMask.CountEnabled())
		//
		//sigs = append(sigs, allResponses.finalResponse.Signature)
		//err = finalMask.Merge(allResponses.finalResponse.Mask)
		//if err != nil {
		//	log.Lvlf3("ERROOOOOOOR211: %v", err)
		//	return err
		//}
		//
		//signaturePoint, err := bdn.AggregateSignatures(p.suite, sigs, finalMask)
		//if err != nil {
		//	log.Lvlf3("ERROOOOOOOR222: %v", err)
		//	return err
		//}
		//
		//signature, err := signaturePoint.MarshalBinary()
		//if err != nil {
		//	return err
		//}

		// Final part
		finalSig := append(allResponses.finalResponse.Signature, allResponses.finalResponse.Mask...)
		log.Lvlf3("%v created final signature %x with mask %b", p.ServerIdentity(), allResponses.finalResponse.Signature, allResponses.finalResponse.Mask)
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

func handleRumor(allResponses *AllResponses, rumor *RumorMessage, p *BlsCosiSubstract) (bool, error) {
	return allResponses.Add(rumor.Rumor, p)
}

func handleSignatureRequest(allResponses *AllResponses, ownId uint32, signatureReq *SignatureRequestMessage, p *BlsCosiSubstract) {
	bitMapResponse := make(BitMap)
	log.Lvlf5("Signature Request received by %d, asking for %d", ownId, signatureReq.SignatureRequest.idx)

	if ownId == signatureReq.SignatureRequest.idx {
		bitMapResponse[ownId] = true
		p.sendRumor(signatureReq.TreeNode, *allResponses.collectedResponses[ownId], bitMapResponse)
	} else {
		if allResponses.collectedMap[signatureReq.SignatureRequest.idx] {
			bitMapResponse[signatureReq.SignatureRequest.idx] = true
			p.sendRumor(signatureReq.TreeNode, *allResponses.collectedResponses[signatureReq.SignatureRequest.idx], bitMapResponse)
		}
	}
}

func (p *BlsCosiSubstract) trySign(allResponses *AllResponses) (*AllResponses, uint32, error) {
	// Create signature
	if !p.verificationFn(p.Msg, p.Data) {
		log.Lvlf4("Node %v refused to sign", p.ServerIdentity())
		return nil, 0, nil
	}
	own, idx, err := p.makeResponse()
	if err != nil {
		return nil, 0, err
	}
	ownMask := make(BitMap)
	ownMask[uint32(idx)] = true

	allResponses.finalResponse = Response{
		Signature: own.Signature,
		Mask:      own.Mask,
	}
	allResponses.finalMap = ownMask
	allResponses.collectedResponses[uint32(idx)] = &Response{
		Signature: own.Signature,
		Mask:      own.Mask,
	}
	allResponses.collectedMap[uint32(idx)] = true

	log.Lvlf4("Node %v signed", p.ServerIdentity())
	return allResponses, uint32(idx), nil
}

// sendRumors sends a rumor message to some random peers.
func (p *BlsCosiSubstract) sendRumors(allResponses AllResponses, ownId uint32) {
	targets, err := p.getRandomPeers(p.Params.RumorPeers)
	if err != nil {
		log.Lvl1("Couldn't get random peers:", err)
		return
	}
	log.Lvl5("Sending rumors")
	for _, target := range targets {
		p.sendRumor(target, allResponses.finalResponse, allResponses.finalMap)
	}
}

// sendRumor sends the given signatures to a peer.
func (p *BlsCosiSubstract) sendRumor(target *onet.TreeNode, response Response, bitMap BitMap) {
	p.SendTo(target, &Rumor{p.Params, response, bitMap, p.Msg})
}

// sendSignatureRequest sends a signature request message to a peer.
func (p *BlsCosiSubstract) sendSignatureRequest(target *onet.TreeNode, idx uint32) {
	test := make([]int, 1)
	test[0] = 1
	p.SendTo(target, &SignatureRequest{idx, p.Msg})
}

// sendShutdowns sends a shutdown message to some random peers.
func (p *BlsCosiSubstract) sendShutdowns(shutdown Shutdown) {
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
func (p *BlsCosiSubstract) sendShutdown(target *onet.TreeNode, shutdown Shutdown) {
	p.SendTo(target, &shutdown)
}

// verifyShutdown verifies the legitimacy of a shutdown message.
func (p *BlsCosiSubstract) verifyShutdown(msg ShutdownMessage) error {
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
func (p *BlsCosiSubstract) getRandomPeers(numTargets int) ([]*onet.TreeNode, error) {
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
func (p *BlsCosiSubstract) checkIntegrity() error {
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
func (p *BlsCosiSubstract) checkFailureThreshold(numFailure int) bool {
	return numFailure > len(p.Roster().List)-p.Threshold
}

// Sign the message and pack it with the mask as a response
// idx is this node's index
func (p *BlsCosiSubstract) makeResponse() (*Response, int, error) {
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

	return &Response{
		Signature: sig,
		Mask:      mask.Mask(),
	}, idx, nil
	//// Multiply signature with its coefficient immediately
	//sigAdd := [][]byte{sig}
	//maskAdd, err := sign.NewMask(p.suite, p.Publics(), nil)
	//if err != nil {
	//	return nil, 0, err
	//}
	//maskAdd.Merge(mask.Mask())
	//aggSig, err := bdn.AggregateSignatures(p.suite, sigAdd, maskAdd)
	//if err != nil {
	//	return nil, 0, err
	//}
	//data, err := aggSig.MarshalBinary()
	//if err != nil {
	//	return nil, 0, err
	//}
	//
	//return &Response{
	//	Signature: data,
	//	Mask:      maskAdd.Mask(),
	//}, idx, nil
}

func aggregateSignatures(p *BlsCosiSubstract, response1 Response, response2 Response) (*Response, error) {
	//// FIRST TRY USING BLS
	//mask, err := sign.NewMask(p.suite, p.Publics(), nil)
	//if err != nil {
	//	return nil, err
	//}
	//mask.Merge(response1.Mask)
	//mask.Merge(response2.Mask)
	//
	//sig, err := bls.AggregateSignatures(p.suite, response1.Signature, response2.Signature)
	//if err != nil {
	//	return nil, err
	//}
	//
	//return &Response{sig, mask.Mask()}, nil

	//SECOND TRY USING BDN
	mask, err := sign.NewMask(p.suite, p.Publics(), nil)
	if err != nil {
		return nil, err
	}
	mask.Merge(response1.Mask)
	mask.Merge(response2.Mask)

	finalPoint := p.suite.G1().Point()
	err = finalPoint.UnmarshalBinary(response1.Signature)
	if err != nil {
		return nil, err
	}

	secondPoint := p.suite.G1().Point()
	err = secondPoint.UnmarshalBinary(response2.Signature)
	if err != nil {
		return nil, err
	}

	finalPoint = finalPoint.Add(finalPoint, secondPoint)
	if err != nil {
		return nil, err
	}

	data, err := finalPoint.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return &Response{data, mask.Mask()}, nil
}

func aggregateMaps(map1 BitMap, map2 BitMap) BitMap {
	aggMap := make(BitMap)
	for key := range map1 {
		aggMap[key] = true
	}
	for key := range map2 {
		aggMap[key] = true
	}
	return aggMap
}

func substractSignatures(p *BlsCosiSubstract, response1 Response, response2 Response, idx int) (*Response, error) {
	//substractedMask := make([]byte, len(response1.Mask))
	//for i := range response1.Mask {
	//	if response2.Mask[i] == 1 {
	//		substractedMask[i] = 0
	//	} else {
	//		substractedMask[i] = response1.Mask[i]
	//	}
	//}

	byteIndex := idx / 8
	mask := byte(1) << uint(idx&7)
	response1.Mask[byteIndex] ^= mask

	finalPoint := p.suite.G1().Point()
	err := finalPoint.UnmarshalBinary(response1.Signature)
	if err != nil {
		return nil, err
	}

	secondPoint := p.suite.G1().Point()
	err = secondPoint.UnmarshalBinary(response2.Signature)
	if err != nil {
		return nil, err
	}

	finalPoint = finalPoint.Sub(finalPoint, secondPoint)

	data, err := finalPoint.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return &Response{data, response1.Mask}, nil
}
