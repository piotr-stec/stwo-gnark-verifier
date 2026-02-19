package components

import (
	"fmt"
	"strings"

	"github.com/HerodotusDev/stwo-gnark-verifier/circle"

	// "github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// TreeMaskPoints contains the sample points for each tree.
// [tree][column][point_index]
type TreeMaskPoints [][][]circle.Point

// ComputeGenericMaskPoints computes mask points for generic verification based on VerificationParams
// This is analogous to Rust's Components::mask_points
func ComputeGenericMaskPoints(
	api frontend.API,
	uapi *uints.BinaryField[uints.U32],
	circleChip *circle.CircleChip,
	oodsPoint circle.Point,
	params variables.VerificationParams,
) TreeMaskPoints {
	// Calculate total number of trees from column log sizes
	nTrees := len(params.TreeColumnLogSizes)

	// Initialize mask points structure - start with empty, columns will be created dynamically
	// (like Rust's TreeVec::concat_cols which doesn't pre-allocate)
	maskPoints := make(TreeMaskPoints, nTrees)
	for treeIdx := range maskPoints {
		// Initialize with map to track which columns exist
		maskPoints[treeIdx] = make([][]circle.Point, 0)
	}

	// Step 1: Process mask offsets for all components (like Rust's TreeVec::concat_cols)
	for componentIdx, componentParam := range params.ComponentParams {
		maskPoints = processComponentMaskOffsets(
			api,
			uapi,
			circleChip,
			oodsPoint,
			componentParam,
			componentIdx,
			maskPoints,
		)
	}

	// Step 2: Process preprocessed columns - set them to OODS point (like Rust does at the end)
	// This must happen AFTER all mask offsets are processed
	maskPoints = processPreprocessedColumns(
		maskPoints,
		oodsPoint,
		params,
	)

	// Debug: print structure
	for treeIdx, tree := range maskPoints {
		colCounts := make([]string, 0)
		for colIdx, col := range tree {
			if colIdx < 5 || colIdx >= len(tree)-2 {
				colCounts = append(colCounts, fmt.Sprintf("[%d]=%d", colIdx, len(col)))
			} else if colIdx == 5 {
				colCounts = append(colCounts, "...")
			}
		}
		fmt.Printf("Tree %d has %d columns: %s\n", treeIdx, len(tree), strings.Join(colCounts, " "))
	}

	return maskPoints
}

// processComponentMaskOffsets processes mask offsets for a single component (ONLY offsets, no preprocessed)
// This corresponds to the individual component.mask_points(point) call in Rust
func processComponentMaskOffsets(
	api frontend.API,
	uapi *uints.BinaryField[uints.U32],
	circleChip *circle.CircleChip,
	oodsPoint circle.Point,
	componentParam variables.ComponentParams,
	componentIdx int,
	maskPoints TreeMaskPoints,
) TreeMaskPoints {
	// Get trace step for this component
	traceStep := getTraceStep(circleChip, frontend.Variable(componentParam.LogSize))

	// Process mask offsets from component info (ONLY mask offsets, not preprocessed)
	for treeIdx, treeOffsets := range componentParam.Info.MaskOffsets {
		// Ensure tree exists and expand if needed
		for len(maskPoints) <= treeIdx {
			maskPoints = append(maskPoints, make([][]circle.Point, 0))
		}

		for _, maskOffsets := range treeOffsets {
			// Compute mask points for this column
			columnMaskPoints := make([]circle.Point, len(maskOffsets))
			for offsetIdx, offset := range maskOffsets {
				columnMaskPoints[offsetIdx] = computeMaskPoint(
					api,
					uapi,
					circleChip,
					oodsPoint,
					traceStep,
					frontend.Variable(uint32(offset)),
				)
			}

			// Add as NEW column (like Rust TreeVec::concat_cols which adds columns, not merges)
			maskPoints[treeIdx] = append(maskPoints[treeIdx], columnMaskPoints)
		}
	}

	return maskPoints
}

// processPreprocessedColumns processes preprocessed columns - first resets all to empty, then fills used ones
// This corresponds to the reset + loop in Rust's Components::mask_points
func processPreprocessedColumns(
	maskPoints TreeMaskPoints,
	oodsPoint circle.Point,
	params variables.VerificationParams,
) TreeMaskPoints {
	// Preprocessed columns are in tree 0
	preprocessedTreeIdx := 0
	if preprocessedTreeIdx >= len(maskPoints) {
		return maskPoints
	}

	// First, ensure tree 0 has enough space for all preprocessed columns
	// and reset ALL preprocessed columns to empty (like Rust does)
	for colIdx := 0; colIdx < params.NPreprocessedColumns; colIdx++ {
		// Expand array if needed
		for len(maskPoints[preprocessedTreeIdx]) <= colIdx {
			maskPoints[preprocessedTreeIdx] = append(maskPoints[preprocessedTreeIdx], nil)
		}
		// Reset to empty
		maskPoints[preprocessedTreeIdx][colIdx] = []circle.Point{}
	}

	// Then, fill in the preprocessed columns that are actually used
	for _, componentParam := range params.ComponentParams {
		for _, preprocessedColIdx := range componentParam.Info.PreprocessedColumns {
			colIdx := preprocessedColIdx
			if colIdx < len(maskPoints[preprocessedTreeIdx]) {
				// Set to single OODS point (like Rust does)
				maskPoints[preprocessedTreeIdx][colIdx] = []circle.Point{oodsPoint}
			}
		}
	}

	return maskPoints
}

// getTraceStep computes the trace generator step for a given log size
// Analogous to Solidity's _getTraceStep
func getTraceStep(circleChip *circle.CircleChip, logSize frontend.Variable) circle.BasePoint {
	coset := circle.NewCanonicCoset(circleChip, logSize)
	stepIndex := coset.Coset().Step()
	return stepIndex.Point()
}

// computeMaskPoint computes a mask point by adding an offset to the base point
// Analogous to Solidity's _computeMaskPoint and Rust's mul_signed
// Offset is interpreted as signed int32 stored in frontend.Variable (as uint32 representation)
func computeMaskPoint(
	api frontend.API,
	uapi *uints.BinaryField[uints.U32],
	circleChip *circle.CircleChip,
	point circle.Point,
	traceStep circle.BasePoint,
	offset frontend.Variable,
) circle.Point {
	// Use BaseMulSigned which handles signed offset correctly:
	// - If offset >= 0: mul(offset)
	// - If offset < 0: neg(mul(-offset))
	offsetPoint := circleChip.BaseMulSigned(traceStep, offset)

	// Add to base point
	return circleChip.AddBasePoint(point, offsetPoint)
}
