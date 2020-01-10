package protocol

import (
	"sort"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/sign"
	"go.dedis.ch/kyber/v3/sign/bdn"
	"go.dedis.ch/onet/v4/log"
)

type SimpleResponses map[uint32]*Response

func (responses SimpleResponses) Add(idx int, response *Response) error {
	responses[uint32(idx)] = response
	return nil
}

func (responses SimpleResponses) Update(newResponses map[uint32](*Response)) error {
	for key, response := range newResponses {
		responses[key] = response
	}
	return nil
}

func (responses SimpleResponses) Count() int {
	return len(responses)
}

func (responses SimpleResponses) Aggregate(suite pairing.Suite, publics []kyber.Point) (
	kyber.Point, *sign.Mask, error) {

	var sigs [][]byte
	aggMask, err := sign.NewMask(suite, publics, nil)
	if err != nil {
		return nil, nil, err
	}

	log.Lvlf3("aggregating total of %d signatures", aggMask.CountEnabled())

	var keys []uint32
	for k := range responses {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for _, k := range keys {
		res := responses[k]
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

func (responses SimpleResponses) Map() map[uint32](*Response) {
	return responses
}
