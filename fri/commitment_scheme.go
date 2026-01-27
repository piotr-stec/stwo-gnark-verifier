package fri

import (
	"fmt"
	"sort"

	"github.com/HerodotusDev/stwo-gnark-verifier/channel"
	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// CommitmentSchemeVerifier mirrors the prover-side Merkle commitment verifier.
type CommitmentSchemeVerifier struct {
	api                frontend.API
	uapi               *uints.BinaryField[uints.U32]
	PcsConfig          variables.PcsConfig
	Trees              []*MerkleVerifier
	TreeColumnLogSizes [][]int // Blew up log sizes if needed? No, these are base log sizes
}

// NewCommitmentSchemeVerifierGeneric initializes the commitment scheme verifier with generic parameters
// This version accepts tree roots and column log sizes directly
func NewCommitmentSchemeVerifierGeneric(
	api frontend.API,
	uapi *uints.BinaryField[uints.U32],
	channel *channel.Channel,
	pcsConfig variables.PcsConfig,
	treeRoots [][32]frontend.Variable,
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

func (v *CommitmentSchemeVerifier) initializeTree(treeIndex int, rootRaw [32]frontend.Variable, logSizes []int, ch *channel.Channel) {
	// DEBUG: Check incoming root values
	fmt.Printf("DEBUG initializeTree START: treeIndex=%d, rootRaw[0]=%v, rootRaw[1]=%v\n", treeIndex, rootRaw[0], rootRaw[1])

	// Compute blew up log sizes
	logBlowupFactor := v.PcsConfig.FriConfig.LogBlowupFactor
	columnLogSizes := make([]frontend.Variable, len(logSizes))
	for i, logSize := range logSizes {
		columnLogSizes[i] = frontend.Variable(logSize + logBlowupFactor)
	}

	// Compute nDomainPerLogSize for this tree
	maxLogSize := 0
	for _, ls := range logSizes {
		if ls > maxLogSize {
			maxLogSize = ls
		}
	}
	// Blowup
	maxLogSize += logBlowupFactor

	nDomainPerLogSize := make([]int, maxLogSize+1)
	for _, ls := range logSizes {
		blownUpLs := ls + logBlowupFactor
		if blownUpLs < len(nDomainPerLogSize) {
			nDomainPerLogSize[blownUpLs]++
		}
	}

	fmt.Printf("DEBUG initializeTree END: creating MerkleVerifier\n")
	v.Trees[treeIndex] = NewMerkleVerifier(v.api, v.uapi, rootRaw, columnLogSizes, nDomainPerLogSize)
}

// Commit mixes the Merkle root into the channel and stores the verifier for the tree.
func (v *CommitmentSchemeVerifier) Commit(treeIndex int, rootRaw [32]frontend.Variable, logSizes []int, ch *channel.Channel) {
	if treeIndex < 0 || treeIndex >= len(v.Trees) {
		panic("invalid tree index")
	}
	if ch == nil {
		panic("channel must not be nil")
	}
	// Mix root into channel (convert to uints.U8 first)
	ch.MixRootBytesVar(rootRaw[:])

	// Compute extended log sizes (with blowup) like Rust:
	// extended_log_sizes = log_sizes.map(|&log_size| log_size + log_blowup_factor)
	logBlowupFactor := v.PcsConfig.FriConfig.LogBlowupFactor
	extendedLogSizes := make([]int, len(logSizes))
	for i, logSize := range logSizes {
		extendedLogSizes[i] = logSize + logBlowupFactor
	}

	// Update log sizes (store extended/blew up sizes)
	// If TreeColumnLogSizes is too short, extend it
	if treeIndex >= len(v.TreeColumnLogSizes) {
		// Extend to fit
		newLogSizes := make([][]int, treeIndex+1)
		copy(newLogSizes, v.TreeColumnLogSizes)
		v.TreeColumnLogSizes = newLogSizes
	}
	v.TreeColumnLogSizes[treeIndex] = extendedLogSizes

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
	// TreeColumnLogSizes now stores blew up sizes (after Commit fix)
	uniqueBlownUpSizes := make(map[int]struct{})
	for _, treeSizes := range v.TreeColumnLogSizes {
		for _, blownUpSize := range treeSizes {
			uniqueBlownUpSizes[blownUpSize] = struct{}{}
		}
	}

	// Convert to slice and subtract blowup factor to get degree bounds
	bounds := make([]int, 0, len(uniqueBlownUpSizes))
	for blownUpSize := range uniqueBlownUpSizes {
		degreeBound := blownUpSize - logBlowupFactor
		bounds = append(bounds, degreeBound)
	}

	// Sort descending
	sort.Sort(sort.Reverse(sort.IntSlice(bounds)))

	return bounds
}
