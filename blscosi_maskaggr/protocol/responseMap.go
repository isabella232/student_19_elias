package protocol

import (
	"go.dedis.ch/kyber/v3/sign"
	"go.dedis.ch/kyber/v3/sign/bls"
	"reflect"
)

type BitMap map[uint32]bool

type AllResponses struct {
	OwnSignature        Response
	OwnMap              BitMap
	BuiltResponse       Response
	BuiltMap            BitMap
	AggregatedResponses []*Response
	AggregatedMaps      []BitMap
}

func NewAllResponses(ownSignature Response, ownMap BitMap, builtResponse Response, builtMap BitMap,
	aggregatedResponses []*Response, aggregatedMaps []BitMap) *AllResponses {
	return &AllResponses{ownSignature,
		ownMap,
		builtResponse,
		builtMap,
		aggregatedResponses,
		aggregatedMaps,
	}
}

func (allResponses *AllResponses) Add(rumor Rumor, p *BlsCosiMaskAggr) (bool, *Response, error) {
	if len(rumor.ResponseMask) == 1 {
		isEnough, finalResponse, err := allResponses.insertToBuiltResponse(rumor, p)
		if err != nil {
			return false, nil, err
		}

		if isEnough {
			return true, finalResponse, nil
		}
	}

	enoughSig, finalResponse, err := allResponses.insertToAggregateResponses(rumor, p)
	if err != nil {
		return false, nil, err
	}
	if enoughSig {
		return true, finalResponse, nil
	}

	return false, nil, nil
}

func (allResponses *AllResponses) insertToBuiltResponse(rumor Rumor, p *BlsCosiMaskAggr) (bool, *Response, error) {
	if !hasConflict(rumor.ResponseMask, allResponses.BuiltMap) {
		aggResponse, err := aggregateSignatures(allResponses.BuiltResponse, rumor.Response, p)

		if err != nil {
			return false, nil, err
		}
		for index, isEnabled := range rumor.ResponseMask {
			if isEnabled {
				allResponses.BuiltMap[index] = true
			}
		}
		allResponses.BuiltResponse = Response{
			aggResponse.Signature,
			aggResponse.Mask,
		}
		enoughSig, finalResponse := allResponses.findEnoughSigBuilt(p.Threshold)
		if enoughSig {
			return true, finalResponse, nil
		}
	}

	return false, nil, nil
}

func aggregateSignatures(response1 Response, response2 Response, p *BlsCosiMaskAggr) (*Response, error) {
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
}

func getSignatureIds(bitMap BitMap) []uint32 {
	signatureIds := make([]uint32, 0)

	for index, isEnabled := range bitMap {
		if isEnabled {
			signatureIds = append(signatureIds, index)
		}
	}
	return signatureIds
}

func hasConflict(bitMap1 BitMap, bitMap2 BitMap) bool {
	for index, isEnabled1 := range bitMap1 {
		if isEnabled1 && bitMap2[index] {
			return true
		}
	}
	return false
}

func (allResponses *AllResponses) findEnoughSig(threshold int) (bool, *Response) {
	found, response := allResponses.findEnoughSigBuilt(threshold)
	if found {
		return found, response
	}
	found, response = allResponses.findEnoughSigAggregated(threshold)
	return found, response
}

func (allResponses *AllResponses) findEnoughSigBuilt(threshold int) (bool, *Response) {
	if len(allResponses.BuiltMap) >= threshold {
		return true, &allResponses.BuiltResponse
	} else {
		return false, nil
	}
}

func (allResponses *AllResponses) findEnoughSigAggregated(threshold int) (bool, *Response) {
	for index, response := range allResponses.AggregatedResponses {
		if len(allResponses.AggregatedMaps[index]) >= threshold {
			return true, response
		}
	}
	return false, nil
}

func enoughSigSingleResponse(bitMap BitMap, threshold int) bool {
	return len(bitMap) >= threshold
}

func (allResponses *AllResponses) insertToAggregateResponses(rumor Rumor, p *BlsCosiMaskAggr) (bool, *Response, error) {
	newResponses := make([]*Response, 0)
	newBitMaps := make([]BitMap, 0)

	if enoughSigSingleResponse(rumor.ResponseMask, p.Threshold) {
		return true, &rumor.Response, nil
	} else {
		if findIndexResponse(allResponses.AggregatedMaps, rumor.ResponseMask) == -1 &&
			findIndexResponse(newBitMaps, rumor.ResponseMask) == -1 {
			copyResponseMask := make(BitMap)
			for indexMask := range rumor.ResponseMask {
				copyResponseMask[indexMask] = true
			}
			newResponses = append(newResponses, &Response{rumor.Response.Signature, rumor.Response.Mask})
			newBitMaps = append(newBitMaps, copyResponseMask)
		}
	}

	for index, aggResponse := range allResponses.AggregatedResponses {
		if !hasConflict(allResponses.AggregatedMaps[index], rumor.ResponseMask) {
			newAggResponse, err := aggregateSignatures(*aggResponse, rumor.Response, p)
			if err != nil {
				return false, nil, err
			}
			newAggMap := make(BitMap)
			for indexMask, isEnabled := range allResponses.AggregatedMaps[index] {
				if isEnabled {
					newAggMap[indexMask] = true
				}
			}
			for indexMask, isEnabled := range rumor.ResponseMask {
				if isEnabled {
					newAggMap[indexMask] = true
				}
			}

			if enoughSigSingleResponse(newAggMap, p.Threshold) {
				return true, newAggResponse, nil
			}
			if findIndexResponse(allResponses.AggregatedMaps, newAggMap) == -1 &&
				findIndexResponse(newBitMaps, newAggMap) == -1 {
				newResponses = append(newResponses, newAggResponse)
				newBitMaps = append(newBitMaps, newAggMap)
			}
		}
	}

	return false, nil, nil
}

func (allResponses *AllResponses) getBestMatch(signatureRequest SignatureRequest, maxLen int) (*Response, BitMap) {
	if isMaskEqual(allResponses.BuiltMap, signatureRequest.Mask) {
		return &allResponses.BuiltResponse, allResponses.BuiltMap
	}

	for index, auxResponse := range allResponses.AggregatedResponses {
		if isMaskEqual(allResponses.AggregatedMaps[index], signatureRequest.Mask) {
			return auxResponse, allResponses.AggregatedMaps[index]
		}
	}

	return nil, nil
}

func findIndexResponse(bitMaps []BitMap, bitMap BitMap) int {
	for index, auxMap := range bitMaps {
		if isMaskEqual(auxMap, bitMap) {
			return index
		}
	}
	return -1
}

func isMaskEqual(mask1 BitMap, mask2 BitMap) bool {
	return reflect.DeepEqual(mask1, mask2)
}
