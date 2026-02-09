package variables

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// ComponentInfo contains metadata about a component for verification
// Analogous to Solidity's ComponentInfo
type ComponentInfo struct {
	// Maximum constraint log degree bound for this component
	MaxConstraintLogDegreeBound int
	// Log size of the component
	LogSize int
	// Mask offsets for each tree, column, and offset value [tree][column][offset_values]
	MaskOffsets [][][]int
	// Preprocessed column IDs
	PreprocessedColumns []int
}

// ComponentParams contains parameters for a single component
// Analogous to Solidity's ComponentParams
type ComponentParams struct {
	// Log size of the trace for this component
	LogSize int
	// Claimed sum for logup constraints (QM31 value)
	ClaimedSum m31.QM31
	// Component metadata
	Info ComponentInfo
}

// VerificationParams contains all parameters needed for verification
// This structure makes the verifier generic and not Cairo-specific
// Analogous to Solidity's VerificationParams
type VerificationParams struct {
	// Array of component parameters
	ComponentParams []ComponentParams
	// Number of preprocessed columns across all components
	NPreprocessedColumns int
	// Composition polynomial log degree bound
	ComponentsCompositionLogDegreeBound int
	// Tree roots for commitment verification (32 bytes per root)
	// Stored as frontend.Variable (bytes) for witness compatibility
	TreeRoots [][32]uints.U8
	// Column log sizes for each tree [tree][column]
	TreeColumnLogSizes [][]int
	// Digest for Fiat-Shamir channel initialization (8 x 32-bit words)
	Digest [8]frontend.Variable
	// Number of randomness draws
	NDraws frontend.Variable
}

// CircuitData contains additional data used to compile the circuit.
// Fields are constants and specific to a given proof.
type CircuitData struct {
	// NColumnsPerLogSize contains the number of columns per log size for each tree (preprocessed, main, interaction and cp).
	// log sizes of NColumnsPerLogSize are not blew up by the [fri.FriConfig.LogBlowupFactor].
	NColumnsPerLogSize [][]int
	// ColumnLogSizes contains the ordered log sizes of the columns for each tree.
	// log sizes of ColumnLogSizes are not blew up.
	ColumnLogSizes [][]int
	// ColumnBounds is a deduped slice of blew up log sizes of the columns across all trees.
	// Ordered in descending order.
	ColumnBounds []int
	// DedupedQueriesShape contains the deduplicated number of queries per log size.
	// Meaning there is DedupedQueriesShape[i] queries for log size i.
	DedupedQueriesShape []int
	// QueriesBranching contains the branching pattern for queries per log size.
	// Each entry is a bitmask: bit 0 for left child present, bit 1 for right child present.
	QueriesBranching [][]uint8
	// FriFirstLayerBranching contains branching patterns for the first FRI merkle verification.
	FriFirstLayerBranching [][]uint8
	// FriInnerLayerBranching contains branching patterns for each inner FRI layer merkle verification.
	FriInnerLayerBranching [][][]uint8
	// BoundsLength is len(ColumnBounds)
	BoundsLength int
	// MaxLogSize is max(ColumnBounds)
	MaxLogSize uint8
}