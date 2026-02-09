package utils

// Are considered utils functions that are built directly on top of the gnark library

import (
	// "math/big"
	// "sort"

	"github.com/consensys/gnark/frontend"
	// "github.com/consensys/gnark/std/conversion"
	// "github.com/consensys/gnark/std/lookup/logderivlookup"
	// "github.com/consensys/gnark/std/math/cmp"
	// "github.com/consensys/gnark/std/math/uints"
)

// ╔══════════════════════════════════╗
// ║           Query Utils            ║
// ╚══════════════════════════════════╝


// GenerateQueries folds the base layer queries and deduplicates them layer by layer.
// It returns the deduplicated queries for all layers from root to leaves (exactly maxLogSize + 1 layers).
func GenerateQueries2(api frontend.API, baseLayerQueries []frontend.Variable, nQueries uint8, dedupedQueriesShape []int, maxLogSize uint8) [][]frontend.Variable {
	// initialize the queries array
	queriesDeduped := make([][]frontend.Variable, maxLogSize+1)

	// deduplicate and order the base layer queries
	layerQueriesDeduped, err := api.Compiler().NewHint(DeduplicationHint, dedupedQueriesShape[maxLogSize], baseLayerQueries...)
	if err != nil {
		panic(err)
	}
	layerQueriesDedupedOrdered, err := api.Compiler().NewHint(AscendingOrderHint, dedupedQueriesShape[maxLogSize], layerQueriesDeduped...)
	if err != nil {
		panic(err)
	}
	AssertPartialDeduplication(api, layerQueriesDedupedOrdered, baseLayerQueries)
	AssertAscendingOrder(api, layerQueriesDedupedOrdered)
	queriesDeduped[maxLogSize] = layerQueriesDedupedOrdered

	// build all queries above the base layer
	for l := maxLogSize; l >= 1; l-- {
		queriesDeduped[l-1] = FoldQueries(api, queriesDeduped[l], dedupedQueriesShape[l-1])
	}

	return queriesDeduped
}


// FoldQueries folds the src layer queries and deduplicates/orders them.
func FoldQueries2(api frontend.API, srcQueries []frontend.Variable, nDeduplicatedQueries int) []frontend.Variable {
	// compute the queries for the dst layer (not deduplicated)
	dstQueries := make([]frontend.Variable, len(srcQueries))
	for queryIndex := 0; queryIndex < len(srcQueries); queryIndex++ {
		parentQueryBinary := api.ToBinary(srcQueries[queryIndex], 32)
		parentQueryShifted := api.FromBinary(parentQueryBinary[1:]...)
		dstQueries[queryIndex] = parentQueryShifted
	}

	// deduplicate the queries for the dst layer
	nextLayerQueriesDeduped, err := api.Compiler().NewHint(DeduplicationHint, nDeduplicatedQueries, dstQueries...)
	if err != nil {
		panic(err)
	}
	dstQueriesOrdered, err := api.Compiler().NewHint(AscendingOrderHint, nDeduplicatedQueries, nextLayerQueriesDeduped...)
	if err != nil {
		panic(err)
	}
	AssertPartialDeduplication(api, dstQueriesOrdered, dstQueries)
	AssertAscendingOrder(api, dstQueriesOrdered)
	return dstQueriesOrdered
}
