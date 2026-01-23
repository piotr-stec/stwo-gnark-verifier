package components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/circle"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

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
	traceStep := getTraceStep(circleChip, componentParam.LogSize)

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
					offset,
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
			colIdxInt := api.ToBinary(preprocessedColIdx, 32)
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
	isNegative := api.Cmp(offset, 1<<31)

	// Get absolute value: for negative, abs = 2^32 - offset
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
