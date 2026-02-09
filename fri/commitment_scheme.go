package fri

import (
	"sort"

	"github.com/HerodotusDev/stwo-gnark-verifier/channel"
	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
		"github.com/HerodotusDev/stwo-gnark-verifier/utils"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// CommitmentSchemeVerifier mirrors the prover-side Merkle commitment verifier.
type CommitmentSchemeVerifier struct {
	api                frontend.API
	uapi               *uints.BinaryField[uints.U32]
	PcsConfig          variables.PcsConfig
	Trees              []*MerkleVerifier
	TreeColumnLogSizes [][]int 
}

// NewCommitmentSchemeVerifierGeneric initializes the commitment scheme verifier with generic parameters
// This version accepts tree roots and column log sizes directly
func NewCommitmentSchemeVerifierGeneric(
	api frontend.API,
	uapi *uints.BinaryField[uints.U32],
	channel *channel.Channel,
	pcsConfig variables.PcsConfig,
	treeRoots [][32]uints.U8,
	treeColumnLogSizes [][]int,
) *CommitmentSchemeVerifier {
	numTrees := len(treeRoots)
	verifier := &CommitmentSchemeVerifier{
		api:                api,
		uapi:               uapi,
		PcsConfig:          pcsConfig,
		Trees:              make([]*MerkleVerifier, numTrees),
		TreeColumnLogSizes: treeColumnLogSizes,
	}

	// Initialize trees with provided roots and column log sizes
	for treeIndex := 0; treeIndex < numTrees; treeIndex++ {
		if treeIndex < len(treeColumnLogSizes) {
			verifier.initializeTree(treeIndex, treeRoots[treeIndex], treeColumnLogSizes[treeIndex], channel)
		}
	}

	return verifier
}

func (v *CommitmentSchemeVerifier) initializeTree(treeIndex int, rootRaw [32]uints.U8, logSizes []int, ch *channel.Channel) {
	columnLogSizes := make([]frontend.Variable, len(logSizes))
	for i, logSize := range logSizes {
		columnLogSizes[i] = frontend.Variable(logSize)
	}

	// Compute nDomainPerLogSize for this tree
	maxLogSize := 0
	for _, ls := range logSizes {
		if ls > maxLogSize {
			maxLogSize = ls
		}
	}

	nDomainPerLogSize := make([]int, maxLogSize+1)
	for _, ls := range logSizes {
		if ls < len(nDomainPerLogSize) {
			nDomainPerLogSize[ls]++
		}
	}

	v.Trees[treeIndex] = NewMerkleVerifier(v.api, v.uapi, rootRaw, columnLogSizes, nDomainPerLogSize)
}

// Commit mixes the Merkle root into the channel and stores the verifier for the tree.
func (v *CommitmentSchemeVerifier) Commit(treeIndex int, rootRaw [32]uints.U8, logSizes []int, ch *channel.Channel) {
	if treeIndex < 0 || treeIndex >= len(v.Trees) {
		panic("invalid tree index")
	}
	if ch == nil {
		panic("channel must not be nil")
	}
	// Mix root into channel (convert to uints.U8 first)
	ch.MixRootBytes(rootRaw[:])

	// Update TreeColumnLogSizes with commitment domain log sizes (as provided)
	// If TreeColumnLogSizes is too short, extend it
	if treeIndex >= len(v.TreeColumnLogSizes) {
		// Extend to fit
		newLogSizes := make([][]int, treeIndex+1)
		copy(newLogSizes, v.TreeColumnLogSizes)
		v.TreeColumnLogSizes = newLogSizes
	}
	v.TreeColumnLogSizes[treeIndex] = logSizes

	v.initializeTree(treeIndex, rootRaw, logSizes, ch)
}

// Bounds returns the deduplicated and ordered column bounds (degree bounds)
// This matches Rust's behavior:
// 1. Flatten column_log_sizes from all trees (blew up sizes)
// 2. Sort, reverse, dedup
// 3. Subtract log_blowup_factor to get degree bounds
func (v *CommitmentSchemeVerifier) Bounds() []int {
	logBlowupFactor := v.PcsConfig.FriConfig.LogBlowupFactor

	// Flatten column log sizes from all trees
	// TreeColumnLogSizes stores commitment domain log sizes (base sizes, not blew up)
	uniqueCommitmentSizes := make(map[int]struct{})
	for _, treeSizes := range v.TreeColumnLogSizes {
		for _, commitmentSize := range treeSizes {
			uniqueCommitmentSizes[commitmentSize] = struct{}{}
		}
	}

	// Convert to slice (these are already commitment sizes = degree bound + blowup factor)
	// So degree bound = commitment size - blowup factor
	bounds := make([]int, 0, len(uniqueCommitmentSizes))
	for commitmentSize := range uniqueCommitmentSizes {
		degreeBound := commitmentSize - logBlowupFactor
		bounds = append(bounds, degreeBound)
	}

	// Sort descending
	sort.Sort(sort.Reverse(sort.IntSlice(bounds)))

	return bounds
}

// ColumnLogSizes returns the column log sizes for the given tree (and optionally blew up)
func (v *CommitmentSchemeVerifier) ColumnLogSizes(blowup bool) [][]frontend.Variable {
	columnLogSizes := make([][]frontend.Variable, 4)
	for treeIndex, merkleVerifier := range v.Trees {
		if blowup {
			blewupColumnLogSizes := make([]frontend.Variable, len(merkleVerifier.ColumnLogSizes))
			for i, logSize := range merkleVerifier.ColumnLogSizes {
				blewupColumnLogSizes[i] = v.api.Add(logSize, v.PcsConfig.FriConfig.LogBlowupFactor)
			}
			columnLogSizes[treeIndex] = blewupColumnLogSizes
		} else {
			columnLogSizes[treeIndex] = merkleVerifier.ColumnLogSizes
		}
	}
	return columnLogSizes
}

// Bounds returns the deduplicated and ordered column bounds
func (v *CommitmentSchemeVerifier) Bounds2(shape variables.CircuitData) []frontend.Variable {
	columnLogSizes := v.ColumnLogSizes(false)
	columnLogSizesFlattened := utils.FlattenTree(columnLogSizes)
	dedupedLogSizes, err := v.api.Compiler().NewHint(utils.DeduplicationHint, shape.BoundsLength, columnLogSizesFlattened...)
	if err != nil {
		panic(err)
	}
	dedupedOrderedLogSizes, err := v.api.Compiler().NewHint(utils.DescendingOrderHint, shape.BoundsLength, dedupedLogSizes...)
	if err != nil {
		panic(err)
	}
	utils.AssertDescendingOrder(v.api, dedupedOrderedLogSizes)
	utils.AssertPartialDeduplication(v.api, dedupedOrderedLogSizes, columnLogSizesFlattened)
	return dedupedOrderedLogSizes
}
