package protocol

import (
	"reflect"
)

type ResponsesMap map[uint32]*Response
type BitMap map[uint32]bool

type AllResponses struct {
	collectedResponses ResponsesMap
	collectedMap       BitMap
	finalResponse      Response
	finalMap           BitMap
	pullResponses      []PullResponse
}

type PullResponse struct {
	pResponse    Response
	pMap         BitMap
	subtractMap  BitMap
	aggregateMap BitMap
}

func NewAllResponses(collectedResponses ResponsesMap, collectedMap BitMap, finalResponse Response, finalBitMap BitMap, pullResponses []PullResponse) *AllResponses {
	return &AllResponses{
		collectedResponses,
		collectedMap,
		finalResponse,
		finalBitMap,
		pullResponses,
	}
}

func (allResponses AllResponses) Add(rumor Rumor, p *BlsCosiSubstract) (bool, error) {
	if len(rumor.Map) == 1 {
		var idx uint32
		for key := range rumor.Map {
			idx = key
		}
		if _, ok := allResponses.collectedResponses[idx]; !ok {
			allResponses.collectedResponses[idx] = &Response{
				Signature: rumor.Response.Signature,
				Mask:      rumor.Response.Mask,
			}
			allResponses.collectedMap[idx] = true
		}
		if !allResponses.finalMap[idx] {
			aggResponse, err := aggregateSignatures(p, allResponses.finalResponse, rumor.Response)
			if err != nil {
				return false, err
			}
			aggMap := aggregateMaps(allResponses.finalMap, rumor.Map)
			allResponses.finalResponse = *aggResponse
			allResponses.finalMap = aggMap

			//log.Lvlf3("Inserted %v", len(allResponses.finalMap))
			if allResponses.isEnough(p) {
				return true, nil
			}

			allResponses.updatePullResponses(p, idx)
			allResponses.mergePullResponses(p)
			if allResponses.isEnough(p) {
				return true, nil
			}
		}
	} else {
		inserted, mapOfRequests := allResponses.insertPullResponses(p, rumor)
		if inserted {
			allResponses.mergePullResponses(p)
			if allResponses.isEnough(p) {
				return true, nil
			} else {
				for key := range mapOfRequests {
					p.sendSignatureRequest(p.TreeNodeInstance.List()[int(key)], key)
				}
			}
		}
	}

	return false, nil
}

func (allResponses AllResponses) isEnough(p *BlsCosiSubstract) bool {
	return len(allResponses.finalMap) >= p.Threshold
}

func (allResponses AllResponses) updatePullResponses(p *BlsCosiSubstract, newIdx uint32) {
	newPullResponses := make([]PullResponse, 0)
	for _, pullResponse := range allResponses.pullResponses {
		pullResponse.subtractMap[newIdx] = true
		delete(pullResponse.subtractMap, newIdx)
		if len(pullResponse.subtractMap) != 0 {
			newPullResponses = append(newPullResponses, pullResponse)
		}
	}
	allResponses.pullResponses = newPullResponses
}

func (allResponses AllResponses) mergePullResponses(p *BlsCosiSubstract) {
	delIndex := -1
	for index, pullResponse := range allResponses.pullResponses {
		if containsMap(allResponses.collectedMap, pullResponse.subtractMap) {
			newSignature := &Response{
				Signature: allResponses.finalResponse.Signature,
				Mask:      allResponses.finalResponse.Mask,
			}
			for key := range pullResponse.subtractMap {
				newSignature, _ = substractSignatures(p, *newSignature, *allResponses.collectedResponses[key])
			}
			for key := range pullResponse.aggregateMap {
				newSignature, _ = aggregateSignatures(p, *newSignature, *allResponses.collectedResponses[key])
				allResponses.finalMap[key] = true
			}
			allResponses.finalResponse = *newSignature
			delIndex = index
			break
		}
	}
	if delIndex != -1 {
		allResponses.pullResponses = append(allResponses.pullResponses[:delIndex], allResponses.pullResponses[delIndex+1:]...)
		if allResponses.isEnough(p) {
			return
		}
		allResponses.mergePullResponses(p)
	}
}

func (allResponses AllResponses) insertPullResponses(p *BlsCosiSubstract, rumor Rumor) (bool, BitMap) {
	substractMap := make(BitMap)
	found := false
	for _, pullResponse := range allResponses.pullResponses {
		if isMaskEqual(pullResponse.pMap, rumor.Map) {
			found = true
			break
		}
	}
	if !found {
		subtractMap := make(BitMap)
		aggregateMap := make(BitMap)
		for key := range rumor.Map {
			if allResponses.finalMap[key] {
				subtractMap[key] = true
			} else {
				aggregateMap[key] = true
			}
		}
		allResponses.pullResponses = append(allResponses.pullResponses, PullResponse{
			pResponse: Response{
				rumor.Response.Signature,
				rumor.Response.Mask,
			},
			pMap:         rumor.Map,
			subtractMap:  subtractMap,
			aggregateMap: aggregateMap,
		})
	}
	return !found, substractMap
}

func containsMap(map1 BitMap, map2 BitMap) bool {
	for index := range map2 {
		if !map1[index] {
			return false
		}
	}
	return true
}

func isMaskEqual(mask1 BitMap, mask2 BitMap) bool {
	return reflect.DeepEqual(mask1, mask2)
}
