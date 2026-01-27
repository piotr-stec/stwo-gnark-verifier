package variables

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
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
	TreeRoots [][32]frontend.Variable
	// Column log sizes for each tree [tree][column]
	TreeColumnLogSizes [][]int
	// Digest for Fiat-Shamir channel initialization (8 x 32-bit words)
	Digest [8]frontend.Variable
	// Number of randomness draws
	NDraws frontend.Variable
}
