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
	MaxConstraintLogDegreeBound frontend.Variable
	// Log size of the component
	LogSize frontend.Variable
	// Mask offsets for each tree, column, and offset value [tree][column][offset_values]
	MaskOffsets [][][]frontend.Variable
	// Preprocessed column IDs
	PreprocessedColumns []frontend.Variable
}

// ComponentParams contains parameters for a single component
// Analogous to Solidity's ComponentParams
type ComponentParams struct {
	// Log size of the trace for this component
	LogSize frontend.Variable
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
	NPreprocessedColumns frontend.Variable
	// Composition polynomial log degree bound
	ComponentsCompositionLogDegreeBound frontend.Variable
	// Tree roots for commitment verification (32 bytes per root)
	TreeRoots [][32]uints.U8
	// Column log sizes for each tree [tree][column]
	TreeColumnLogSizes [][]frontend.Variable
	// Digest for Fiat-Shamir channel initialization (8 x 32-bit words = 32 bytes)
	Digest [8]uints.U32
	// Number of randomness draws
	NDraws frontend.Variable
}
