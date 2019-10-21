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

	// responses is where we collect all signatures.
	var response *Response
	collectedSignatures := NewRumorResponses(make(ResponsesMap), make(BitMap))
	pullingResponses := make([]*Response, 0)
	pullingCollisionMasks := make([][]byte, 0)

	// Add own signature.
	ownId, err := p.trySign(response, collectedSignatures)
	if err != nil || response == nil {
		return err
	}

	if rumor != nil {
		shutdown, err = handleRumor(response, collectedSignatures, pullingResponses, pullingCollisionMasks, rumor, p)
		if err != nil {
			return err
		}
	}

	ticker := time.NewTicker(p.Params.GossipTick)
	for !shutdown {
		select {
		case rumor := <-p.RumorsChan:
			shutdown, err = handleRumor(response, collectedSignatures, pullingResponses, pullingCollisionMasks, &rumor, p)
			if err != nil {
				return err
			}
		case signatureRequest := <-p.SignatureRequestChan:
			handleSignatureRequest(collectedSignatures, &signatureRequest, p)
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
			p.sendRumors(*collectedSignatures, ownId)
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
		finalMask, err := sign.NewMask(p.suite, p.Publics(), nil)
		if err != nil {
			return err
		}
		finalMask.Merge(response.Mask)

		finalSig := append(response.Signature, finalMask.Mask()...)
		log.Lvlf3("%v created final signature %x with mask %b", p.ServerIdentity(), response.Signature, finalMask.Mask())
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

func handleRumor(response *Response, collectedSignatures *RumorResponses, pullingResponses []*Response, pullingCollisionMasks [][]byte, rumor *RumorMessage, p *BlsCosiSubstract) (bool, error) {
	isSingle, idx := isSingleSignature(*rumor)
	if isSingle && collectedSignatures.SelectById(idx) == nil {
		collectedSignatures.Add(int(idx), rumor.Rumor.Response)
	}
	added := addToResponseOrPull(response, collectedSignatures, pullingResponses, pullingCollisionMasks, *rumor, p)
	if added {
		if p.IsRoot() && p.isEnough(*response) {
			return true, nil
		}
		return checkPullingResponses(response, collectedSignatures, pullingResponses, pullingCollisionMasks, p), nil
	}
	return false, nil
}

func handleSignatureRequest(collectedSignatures *RumorResponses, signatureReq *SignatureRequestMessage, p *BlsCosiSubstract) {
	pullReply := collectedSignatures.SelectById(signatureReq.SignatureRequest.idx)
	p.sendRumor(signatureReq.TreeNode, *pullReply)
}

func (p *BlsCosiSubstract) trySign(response *Response, collectedSignatures *RumorResponses) (uint32, error) {
	// Create signature
	if !p.verificationFn(p.Msg, p.Data) {
		log.Lvlf4("Node %v refused to sign", p.ServerIdentity())
		return 0, nil
	}
	own, idx, err := p.makeResponse()
	if err != nil {
		return 0, err
	}
	// Multiply signature with coefficient immediately
	mask, err := sign.NewMask(p.suite, p.Publics(), nil)
	if err != nil {
		return 0, err
	}
	mask.Merge(own.Mask)
	sig := [][]byte{own.Signature}
	aggSig, err := bdn.AggregateSignatures(p.suite, sig, mask)
	if err != nil {
		return 0, err
	}
	finalSign, err := aggSig.MarshalBinary()
	if err != nil {
		return 0, err
	}
	response = &Response{
		Signature: finalSign,
		Mask:      mask.Mask(),
	}
	collectedSignatures.Add(idx, *response)
	log.Lvlf4("Node %v signed", p.ServerIdentity())
	return uint32(idx), nil
}

// sendRumors sends a rumor message to some random peers.
func (p *BlsCosiSubstract) sendRumors(collectedSignatures RumorResponses, ownId uint32) {
	targets, err := p.getRandomPeers(p.Params.RumorPeers)
	if err != nil {
		log.Lvl1("Couldn't get random peers:", err)
		return
	}
	ownSignatureOnly := collectedSignatures.responsesMap[ownId]
	log.Lvl5("Sending rumors")
	for _, target := range targets {
		p.sendRumor(target, *ownSignatureOnly)
	}
}

// sendRumor sends the given signatures to a peer.
func (p *BlsCosiSubstract) sendRumor(target *onet.TreeNode, response Response) {
	p.SendTo(target, &Rumor{p.Params, response, p.Msg})
}

// sendSignatureRequest sends a signature request message to a peer.
func (p *BlsCosiSubstract) sendSignatureRequest(target *onet.TreeNode, idx uint32) {
	p.SendTo(target, &SignatureRequest{idx})
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

// isEnough returns true if we have enough responses.
func (p *BlsCosiSubstract) isEnough(response Response) bool {
	count := 0
	for _, val := range response.Mask {
		if val == 1 {
			count = count + 1
		}
	}
	return count >= p.Threshold
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
		Mask:      mask.Mask(),
		Signature: sig,
	}, idx, nil
}

func isSingleSignature(rumor RumorMessage) (bool, uint32) {
	var idSignature uint32
	countSignatures := 0
	for i, item := range rumor.Rumor.Response.Mask {
		if item == 1 {
			countSignatures++
			idSignature = uint32(i)
		}
	}
	return countSignatures == 1, idSignature
}

func aggregateSignatures(p *BlsCosiSubstract, response1 Response, response2 Response) (*Response, error) {
	// FIRST TRY USING BLS
	mask, err := sign.NewMask(p.suite, p.Publics(), nil)
	if err != nil {
		return nil, err
	}
	mask.Merge(response1.Mask)
	mask.Merge(response2.Mask)

	sig, err := bls.AggregateSignatures(p.suite, response1.Signature, response2.Signature)
	if err != nil {
		return nil, err
	}

	return &Response{sig, mask.Mask()}, nil

	// SECOND TRY USING BDN
	//mask, err := sign.NewMask(p.suite, p.Publics(), nil)
	//if err != nil {
	//	return nil, err
	//}
	//mask.Merge(response1.Mask)
	//mask.Merge(response2.Mask)
	//
	//finalPoint := p.suite.G1().Point()
	//err = finalPoint.UnmarshalBinary(response1.Signature)
	//if err != nil {
	//	return nil, err
	//}
	//
	//secondPoint := p.suite.G1().Point()
	//err = secondPoint.UnmarshalBinary(response2.Signature)
	//if err != nil {
	//	return nil, err
	//}
	//var sigs [][]byte
	//sigs = append(sigs, response1.Signature)
	//sigs = append(sigs, response2.Signature)
	//
	//aggSig, err := bdn.AggregateSignatures(p.suite, sigs, mask)
	//
	//data, err := aggSig.MarshalBinary()
	//if err != nil {
	//	return nil, err
	//}
	//
	//return &Response{data, mask.Mask()}, nil
}

func addToResponseOrPull(response *Response, collectedSignatures *RumorResponses, pullingResponses []*Response, pullingCollisionMasks [][]byte, rumor RumorMessage, p *BlsCosiSubstract) bool {
	collision, newValues := masksCollision(rumor.Rumor.Response.Mask, response.Mask)
	if len(collision) == 0 && newValues > 0 {
		response, _ = aggregateSignatures(p, *response, rumor.Rumor.Response)
		return true
	} else if len(collision) > 0 && newValues > 0 {
		pullingResponses = append(pullingResponses, &Response{
			Signature: rumor.Rumor.Response.Signature,
			Mask:      rumor.Rumor.Response.Mask,
		})
		pullingCollisionMasks = append(pullingCollisionMasks, createMaskFromIndexList(collision, len(rumor.Rumor.Response.Mask)))
		return true
	}
	return false
}

func masksCollision(mask1 []byte, mask2 []byte) ([]uint32, uint32) {
	collision := make([]uint32, 0)
	newValues := uint32(0)
	for i := range mask1 {
		if mask1[i] == 1 && mask2[i] == 1 {
			collision = append(collision, uint32(i))
		}
		if mask1[i] == 1 && mask2[i] == 0 || mask1[i] == 0 && mask2[i] == 1 {
			newValues = newValues + 1
		}
	}
	return collision, newValues
}

func createMaskFromIndexList(indexes []uint32, maskLen int) []byte {
	mask := make([]byte, maskLen)
	for _, index := range indexes {
		mask[index] = 1
	}
	return mask
}

func checkPullingResponses(response *Response, collectedSignatures *RumorResponses, pullingResponses []*Response, pullingCollisionMasks [][]byte, p *BlsCosiSubstract) bool {
	signatureRequestIds := make(map[uint32]bool)
	for i, pullRes := range pullingResponses {
		contains, substractIds := bitmapContainsMask(collectedSignatures.bitMap, pullingCollisionMasks[i])
		if contains {
			substractedSignature := &Response{
				Signature: response.Signature,
				Mask:      response.Mask,
			}
			for _, idx := range substractIds {
				substractedSignature, _ = substractSignatures(p, *substractedSignature, *collectedSignatures.SelectById(idx))
			}
			response, _ = aggregateSignatures(p, *substractedSignature, *pullRes)
			pullingResponses = append(pullingResponses[:i], pullingResponses[i+1:]...)
			pullingCollisionMasks = append(pullingCollisionMasks[:i], pullingCollisionMasks[i+1:]...)
			if p.IsRoot() && p.isEnough(*response) {
				return true
			}
			return checkPullingResponses(response, collectedSignatures, pullingResponses, pullingCollisionMasks, p)
		} else {
			for _, idx := range substractIds {
				signatureRequestIds[idx] = true
			}
		}
	}

	for keyIdx := range signatureRequestIds {
		p.sendSignatureRequest(p.TreeNodeInstance.List()[int(keyIdx)], keyIdx)
	}

	return false
}

func bitmapContainsMask(mask BitMap, submask []byte) (bool, []uint32) {
	substractIds := make([]uint32, 0)
	missingIds := make([]uint32, 0)
	contains := true
	for i := range submask {
		if submask[i] == 1 {
			if mask[uint32(i)] {
				substractIds = append(substractIds, uint32(i))
			} else {
				contains = false
				missingIds = append(substractIds, uint32(i))
			}
		}
	}
	if contains {
		return contains, substractIds
	} else {
		return contains, missingIds
	}
}

func substractSignatures(p *BlsCosiSubstract, response1 Response, response2 Response) (*Response, error) {
	substractedMask := make([]byte, len(response1.Mask))
	for i := range response1.Mask {
		if response2.Mask[i] == 1 {
			substractedMask[i] = 0
		} else {
			substractedMask[i] = response1.Mask[i]
		}
	}

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

	return &Response{data, substractedMask}, nil
}
