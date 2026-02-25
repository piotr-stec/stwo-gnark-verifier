package components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/circle"
	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// TreeMaskPoints contains the sample points for each tree.
// [tree][column][point_index]
type TreeMaskPoints [][][]circle.Point

// maskPointCacheKey uniquely identifies a mask point by its (logSize, signed-offset) pair.
// Points with the same key are mathematically equal and must share the same circuit wire
// so that FriQuotientEvaluations2's PointKey-based grouping works correctly in circuit mode.
type maskPointCacheKey struct {
	logSize int
	offset  int32
}

// ComputeGenericMaskPoints computes mask points for generic verification based on VerificationParams.
// This is analogous to Rust's Components::mask_points.
//
// CRITICAL: Each unique (logSize, offset) pair is computed ONCE and its circuit wire is reused
// for all columns sharing that pair.  This ensures the fmt.Sprintf-based PointKey in
// FriQuotientEvaluations2 correctly groups samples during circuit compilation (groth16.Prove),
// not just during test.IsSolved evaluation.
func ComputeGenericMaskPoints(
	api frontend.API,
	uapi *uints.BinaryField[uints.U32],
	circleChip *circle.CircleChip,
	oodsPoint circle.Point,
	params variables.VerificationParams,
) TreeMaskPoints {
	nTrees := len(params.TreeColumnLogSizes)

	maskPoints := make(TreeMaskPoints, nTrees)
	for treeIdx := range maskPoints {
		maskPoints[treeIdx] = make([][]circle.Point, 0)
	}

	// Compute traceStep for each unique logSize exactly once so that
	// columns in different components with the same logSize share the same wire.
	traceStepCache := make(map[int]circle.BasePoint)
	for _, comp := range params.ComponentParams {
		if _, exists := traceStepCache[comp.LogSize]; !exists {
			traceStepCache[comp.LogSize] = getTraceStep(circleChip, frontend.Variable(comp.LogSize))
		}
	}

	// Cache computed mask points.  Offset=0 always returns oodsPoint directly so that
	// trace columns at the OODS point share the exact same wire as composition columns
	// (which are also set to oodsPoint in verifier.go).
	maskCache := make(map[maskPointCacheKey]circle.Point)

	getMaskPoint := func(logSize int, offset int) circle.Point {
		key := maskPointCacheKey{logSize, int32(offset)}
		if cached, ok := maskCache[key]; ok {
			return cached
		}
		var mp circle.Point
		if offset == 0 {
			// Offset 0 → evaluation point is exactly oodsPoint; reuse the same wire.
			mp = oodsPoint
		} else {
			mp = computeMaskPoint(
				api, uapi, circleChip,
				oodsPoint,
				traceStepCache[logSize],
				frontend.Variable(uint32(int32(offset))),
			)
		}
		maskCache[key] = mp
		return mp
	}

	// Step 1: Mask offsets for all components.
	for _, componentParam := range params.ComponentParams {
		for treeIdx, treeOffsets := range componentParam.Info.MaskOffsets {
			for len(maskPoints) <= treeIdx {
				maskPoints = append(maskPoints, make([][]circle.Point, 0))
			}
			for _, maskOffsets := range treeOffsets {
				columnMaskPoints := make([]circle.Point, len(maskOffsets))
				for i, offset := range maskOffsets {
					columnMaskPoints[i] = getMaskPoint(componentParam.LogSize, offset)
				}
				maskPoints[treeIdx] = append(maskPoints[treeIdx], columnMaskPoints)
			}
		}
	}

	// Step 2: Preprocessed columns — evaluated at oodsPoint directly.
	maskPoints = processPreprocessedColumns(maskPoints, oodsPoint, params)

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
