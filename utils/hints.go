package utils

import (
	"math/big"
	"sort"

	"github.com/consensys/gnark/constraint/solver"
)

func init() {
	solver.RegisterHint(DeduplicationHint)
	solver.RegisterHint(AscendingOrderHint)
	solver.RegisterHint(DescendingOrderHint)
	solver.RegisterHint(QueriesBranchingHint)
}

// DeduplicationHint takes a list of big.Ints and returns its deduplicated version.
func DeduplicationHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	seen := make(map[string]bool)
	unique := make([]*big.Int, 0)
	for _, e := range inputs {
		key := e.String()
		if !seen[key] {
			seen[key] = true
			unique = append(unique, e)
		}
	}
	for i := 0; i < len(results); i++ {
		if i < len(unique) {
			results[i] = new(big.Int).Set(unique[i])
		} else {
			// Pad with 1<<32
			results[i] = new(big.Int).SetInt64(1 << 32)
		}
	}
	return nil
}

// AscendingOrderHint takes a list of big.Ints and returns its ascending ordered version.
func AscendingOrderHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	// Create a copy to sort
	sorted := make([]*big.Int, len(inputs))
	for i, e := range inputs {
		sorted[i] = new(big.Int).Set(e)
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Cmp(sorted[j]) < 0 })
	
	for i := 0; i < len(results) && i < len(sorted); i++ {
		results[i] = new(big.Int).Set(sorted[i])
	}
	return nil
}

// DescendingOrderHint takes a list of big.Ints and returns its descending ordered version.
func DescendingOrderHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	// Create a copy to sort
	sorted := make([]*big.Int, len(inputs))
	for i, e := range inputs {
		sorted[i] = new(big.Int).Set(e)
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Cmp(sorted[j]) > 0 })
	
	for i := 0; i < len(results) && i < len(sorted); i++ {
		results[i] = new(big.Int).Set(sorted[i])
	}
	return nil
}

// QueriesBranchingHint computes the branching mask for Merkle verification.
// Inputs: [queriesLayer[...], queriesNextLayer[...]]
// Results: [branchingMask[...]] (same length as queriesLayer)
// Mask: bit 0 (1) = left child present, bit 1 (2) = right child present.
func QueriesBranchingHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	// Inputs are concatenated: queriesLayer then queriesNextLayer
	// We need to know where the split is.
	// We assume len(results) corresponds to len(queriesLayer).
	// So inputs[0:len(results)] is queriesLayer.
	// inputs[len(results):] is queriesNextLayer.
	
	nQueries := len(results)
	if len(inputs) < nQueries {
		// Should not happen if correctly called
		return nil
	}
	
	queriesLayer := inputs[:nQueries]
	queriesNextLayer := inputs[nQueries:]
	
	// Create map for next layer for O(1) lookup
	nextLayerMap := make(map[uint64]bool)
	for _, q := range queriesNextLayer {
		if q.IsUint64() {
			nextLayerMap[q.Uint64()] = true
		}
	}
	
	for i, q := range queriesLayer {
		if !q.IsUint64() {
			results[i] = big.NewInt(0)
			continue
		}
		
		val := q.Uint64()
		mask := 0
		
		if nextLayerMap[2*val] {
			mask |= 1
		}
		if nextLayerMap[2*val+1] {
			mask |= 2
		}
		
		results[i] = big.NewInt(int64(mask))
	}
	
	return nil
}
