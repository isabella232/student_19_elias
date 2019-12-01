package protocol

import (
	"sort"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/sign"
	"go.dedis.ch/kyber/v3/sign/bdn"
	"go.dedis.ch/onet/v4/log"
)

type ResponsesMap map[uint32]*Response
type BitMap map[uint32]bool

type RumorResponses struct {
	responsesMap ResponsesMap
	bitMap       BitMap
}

func NewRumorResponses(responsesMap ResponsesMap, bitMap BitMap) *RumorResponses {
	return &RumorResponses{
		responsesMap: responsesMap,
		bitMap:       bitMap,
	}
}

func (responses RumorResponses) Add(idx int, response *Response) error {
	responses.responsesMap[uint32(idx)] = response
	responses.bitMap[uint32(idx)] = true
	return nil
}

func (responses RumorResponses) Update(newResponsesMap ResponsesMap, newBitMap BitMap) (BitMap, error) {
	for key, response := range newResponsesMap {
		responses.responsesMap[key] = response
		responses.bitMap[key] = true
	}

	for key, _ := range responses.bitMap {
		_, ok := newBitMap[key]
		if ok {
			delete(newBitMap, key)
		}
	}

	return newBitMap, nil
}

func (responses RumorResponses) SelectByBitmap(bitMapFilter BitMap) (*RumorResponses, error) {
	selectedResponses := NewRumorResponses(make(ResponsesMap), make(BitMap))
	for key := range bitMapFilter {
		response, ok := responses.responsesMap[key]
		if ok {
			selectedResponses.responsesMap[key] = response
			selectedResponses.bitMap[key] = true
		}
	}

	return selectedResponses, nil
}

func (responses RumorResponses) OwnSignatureWithMap(ownId uint32) *RumorResponses {
	ownSignature := NewRumorResponses(make(ResponsesMap), responses.bitMap)
	ownSignature.responsesMap[ownId] = responses.responsesMap[ownId]

	return ownSignature
}

func (responses RumorResponses) Aggregate(suite pairing.Suite, publics []kyber.Point) (
	kyber.Point, *sign.Mask, error) {

	var sigs [][]byte
	aggMask, err := sign.NewMask(suite, publics, nil)
	if err != nil {
		return nil, nil, err
	}

	log.Lvlf3("aggregating total of %d signatures", aggMask.CountEnabled())

	var keys []uint32
	for k := range responses.responsesMap {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for _, k := range keys {
		res := responses.responsesMap[k]
		sigs = append(sigs, res.Signature)
		err := aggMask.Merge(res.Mask)
		if err != nil {
			return nil, nil, err
		}
	}

	aggSig, err := bdn.AggregateSignatures(suite, sigs, aggMask)
	if err != nil {
		return nil, nil, err
	}

	return aggSig, aggMask, err
}
