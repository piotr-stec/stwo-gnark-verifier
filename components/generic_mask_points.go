package components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/circle"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// TreeMaskPoints contains the sample points for each tree.
// [tree][column][point_index]
type TreeMaskPoints [][][]circle.Point

// ComputeGenericMaskPoints computes mask points for generic verification based on VerificationParams
// This is analogous to Solidity's FrameworkComponentLib.maskPoints
func ComputeGenericMaskPoints(
	api frontend.API,
	uapi *uints.BinaryField[uints.U32],
	circleChip *circle.CircleChip,
	oodsPoint circle.Point,
	params variables.VerificationParams,
) TreeMaskPoints {
	// Calculate total number of trees from column log sizes
	nTrees := len(params.TreeColumnLogSizes)

	// Initialize mask points structure
	maskPoints := make(TreeMaskPoints, nTrees)
	for treeIdx := range maskPoints {
		if treeIdx < len(params.TreeColumnLogSizes) {
			nColumns := len(params.TreeColumnLogSizes[treeIdx])
			maskPoints[treeIdx] = make([][]circle.Point, nColumns)
		} else {
			maskPoints[treeIdx] = make([][]circle.Point, 0)
		}
	}

	// Process each component
	for componentIdx, componentParam := range params.ComponentParams {
		maskPoints = processComponentMaskPoints(
			api,
			uapi,
			circleChip,
			oodsPoint,
			componentParam,
			componentIdx,
			maskPoints,
		)
	}

	return maskPoints
}

// processComponentMaskPoints processes mask points for a single component
func processComponentMaskPoints(
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

	// Process mask offsets from component info
	for treeIdx, treeOffsets := range componentParam.Info.MaskOffsets {
		if treeIdx >= len(maskPoints) {
			continue
		}

		for colIdx, maskOffsets := range treeOffsets {
			if colIdx >= len(maskPoints[treeIdx]) {
				continue
			}

			// Compute mask points for this column
			columnMaskPoints := make([]circle.Point, len(maskOffsets))
			for offsetIdx, offset := range maskOffsets {
				columnMaskPoints[offsetIdx] = computeMaskPoint(
					api,
					uapi,
					circleChip,
					oodsPoint,
					traceStep,
					frontend.Variable(offset),
				)
			}

			// Append to existing mask points (handles column reuse)
			maskPoints[treeIdx][colIdx] = append(maskPoints[treeIdx][colIdx], columnMaskPoints...)
		}
	}

	// Process preprocessed columns
	// Preprocessed columns are evaluated only at the oods point
	for _, preprocessedColIdx := range componentParam.Info.PreprocessedColumns {
		// Preprocessed columns are typically in tree 0
		preprocessedTreeIdx := 0
		if preprocessedTreeIdx < len(maskPoints) {
			colIdxInt := api.ToBinary(frontend.Variable(preprocessedColIdx), 32)
			colIdx := 0
			for i := 0; i < len(colIdxInt) && i < 16; i++ {
				if api.IsZero(colIdxInt[i]) == 0 {
					colIdx |= (1 << i)
				}
			}

			if colIdx < len(maskPoints[preprocessedTreeIdx]) {
				// Preprocessed columns get single point at oods
				maskPoints[preprocessedTreeIdx][colIdx] = append(
					maskPoints[preprocessedTreeIdx][colIdx],
					oodsPoint,
				)
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
// Analogous to Solidity's _computeMaskPoint
// Offset is interpreted as signed int32 stored in frontend.Variable
func computeMaskPoint(
	api frontend.API,
	uapi *uints.BinaryField[uints.U32],
	circleChip *circle.CircleChip,
	point circle.Point,
	traceStep circle.BasePoint,
	offset frontend.Variable,
) circle.Point {
	// Check if offset is negative (bit 31 set in int32 representation)
	// We assume offset fits in 32 bits (and is signed)
	// frontend.Variable is large field element.
	// Negative offset like -1 is represented as P-1 (modulo field).
	// But `offset` comes from `int`.
	// If `offset` is -1, `frontend.Variable(-1)` might be huge positive.
	// `api.Cmp` compares large numbers.
	// Solidity uses `int32`.
	// We should probably convert offset to signed representation if needed.
	// But `MaskOffsets` are `int`.
	// If `int` is negative, `frontend.Variable` wraps?
	// Gnark variables are usually unsigned big ints.
	// If we pass -1, it becomes P-1.
	// `api.Cmp(P-1, 1<<31)` will be true (P-1 > 1<<31).
	// So `isNegative` works if we consider P-1 negative.
	// But `1<<31` is the threshold for 32-bit signed.
	// If we strictly follow 32-bit signed logic:
	// A 32-bit int is negative if bit 31 is set.
	// If we map 32-bit int to field element:
	// Positive `x` -> `x`.
	// Negative `x` (e.g. -1) -> `P-1`? Or `2^32 - 1`?
	// The `convertMaskOffsets` function I wrote converts `int32` to `uint32` then `frontend.Variable`.
	// `int32(-1)` -> `uint32(2^32-1)`.
	// `uint32(2^32-1)` is `4294967295`.
	// `1<<31` is `2147483648`.
	// `4294967295 > 2147483648`.
	// So `api.Cmp` returns 1 (strictly greater).
	// `isNegative := api.Cmp(offset, 1<<31)`.
	// If offset is positive (small), Cmp is -1 or 0.
	// If offset is negative (large uint32), Cmp is 1.
	// So `isNegative` check should be `> 0`?
	// `api.Cmp` returns variable (1, 0, -1).
	// `isNegative` needs to be boolean (0 or 1).
	// I should check `Cmp` output.
	// Actually `api.Cmp` is not standard in `frontend.API`. It's `cmp.BoundedComparator`.
	// The code used `api.Cmp` which suggests `api` has it? No, standard `api` has `Cmp` in recent versions?
	// Gnark `frontend.API` has `Cmp(i1, i2 interface{}) frontend.Variable` in older versions?
	// In recent versions `Cmp` is deprecated/removed in favor of `std/math/cmp`.
	// The original code used `api.Cmp`.
	// If `api` has `Cmp`, it returns 1 if i1>i2, 0 if i1=i2, -1 if i1<i2.
	// We want `isNegative` to be 1 if `offset >= 1<<31`.
	
	// Since `offset` is passed as `int` converted to `frontend.Variable` via `uint32` cast (in my `verification_params_raw.go`),
	// Negative values are large positive (>= 2^31).
	// So we check if `offset >= 2^31`.
	// We can use `cmp.NewBoundedComparator`.
	// Or `api.ToBinary` and check bit 31.
	// Since it's 32 bits, `ToBinary` is safe.
	
	offsetBits := api.ToBinary(offset, 32)
	isNegative := offsetBits[31] // Bit 31 is sign bit

	// Get absolute value: for negative, abs = 2^32 - offset
	// If isNegative, `offset` represents `2^32 - |x|`.
	// We want `|x| = 2^32 - offset`.
	// Example: -1 -> 2^32-1. `2^32 - (2^32-1) = 1`. Correct.
	absOffset := api.Select(
		isNegative,
		api.Sub((1<<32), offset),
		offset,
	)

	// Convert to U32
	absOffsetU32 := uapi.ValueOf(absOffset)

	// Multiply traceStep by absolute offset
	offsetPoint := circleChip.BaseMul(traceStep, absOffsetU32)

	// Negate if original offset was negative
	negOffsetPoint := circleChip.BaseNeg(offsetPoint)

	// Select based on sign
	selectedPoint := circle.BasePoint{
		X: m31.M31{Limb: api.Select(isNegative, negOffsetPoint.X.Limb, offsetPoint.X.Limb)},
		Y: m31.M31{Limb: api.Select(isNegative, negOffsetPoint.Y.Limb, offsetPoint.Y.Limb)},
	}

	// Add to base point
	return circleChip.AddBasePoint(point, selectedPoint)
}