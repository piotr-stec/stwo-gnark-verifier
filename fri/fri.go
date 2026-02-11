package fri

import (
	"fmt"

	"github.com/HerodotusDev/stwo-gnark-verifier/channel"
	"github.com/HerodotusDev/stwo-gnark-verifier/circle"
	"github.com/HerodotusDev/stwo-gnark-verifier/components"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/HerodotusDev/stwo-gnark-verifier/utils"
	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/conversion"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/uints"
)

// FriVerifier is a circuit gadget for verifying a FRI proof
type FriVerifier struct {
	api        frontend.API
	uapi       *uints.BinaryField[uints.U32]
	m31Chip    *m31.M31Chip
	qm31Chip   *m31.QM31Chip
	circleChip *circle.CircleChip

	friConfig           variables.FriConfig
	FirstLayerVerifier  FriFirstLayerVerifier
	InnerLayerVerifiers []FriInnerLayerVerifier
	LastLayerPoly       circle.LinePoly
	lastLayerDomain     circle.LineDomain

	// Store log sizes for computing columns
	treeColumnLogSizes [][]int
	bounds             []int
}

func NewFriVerifier(api frontend.API, uapi *uints.BinaryField[uints.U32], channelChip *channel.Channel, qm31Chip *m31.QM31Chip, circleChip *circle.CircleChip, friConfig variables.FriConfig, friProof variables.FriProof, bounds []frontend.Variable, circuitData variables.CircuitData) *FriVerifier {
	// First layer commitment
	channelChip.MixRootBytes(friProof.FirstLayerProof.Commitment[:])

	// First layer verifier
	columncommitmentDomains := make([]circle.CircleDomain, 0)
	for _, bound := range bounds {
		columncommitmentDomains = append(columncommitmentDomains, circle.NewCanonicCoset(circleChip, bound).CircleDomain())
	}
	firstLayerVerifier := FriFirstLayerVerifier{
		columnBounds:            bounds,
		columnCommitmentDomains: columncommitmentDomains,
		proof:                   friProof.FirstLayerProof,
		foldingAlpha:            channelChip.DrawFelt(),
	}

	// Inner layer verifiers
	layerBound := api.Sub(bounds[0], 2) // first bound folded and blew up
	layerDomain := circle.NewLineDomain(circle.NewCoset(circleChip, circle.SubgroupGenerator(circleChip, api.Add(api.Add(layerBound, friConfig.LogBlowupFactor), 2)), api.Add(layerBound, friConfig.LogBlowupFactor)))

	innerLayerVerifiers := make([]FriInnerLayerVerifier, len(friProof.InnerLayerProofs))
	for i, innerLayerProof := range friProof.InnerLayerProofs {
		channelChip.MixRootBytes(innerLayerProof.Commitment[:])
		innerLayerVerifiers[i] = FriInnerLayerVerifier{
			degreeBound:  layerBound,
			domain:       layerDomain,
			foldingAlpha: channelChip.DrawFelt(),
			layerIndex:   i,
			proof:        innerLayerProof,
		}

		// fold layer
		layerBound = api.Sub(layerBound, 1)
		layerDomain = layerDomain.Double()
	}

	// Mix in the last layer
	channelChip.MixFelts(friProof.LastLayerPoly.Coeffs)

	return &FriVerifier{
		api:                 api,
		uapi:                uapi,
		m31Chip:             qm31Chip.M31Chip(),
		qm31Chip:            qm31Chip,
		circleChip:          circleChip,
		friConfig:           friConfig,
		FirstLayerVerifier:  firstLayerVerifier,
		InnerLayerVerifiers: innerLayerVerifiers,
		LastLayerPoly:       friProof.LastLayerPoly,
		lastLayerDomain:     layerDomain,
	}
}

// FriQuotientEvaluations evaluates the FRI quotients returning quotient evaluations for each log size and for each query
//   - columnLogSizes: log sizes of each column (blew up) for each tree
//   - sampledValues: sampled values for each column for each tree
//   - sampledPoints: sampled points (or "mask points") for each tree, the shape should exactly match the shape of sampledValues
//   - queries: query positions per log size
//   - queriedValues: column values queried for each tree ordered by log size then by query position (same as merkle decommitments)
//   - randomCoeff: random coefficient used to batch lines with the same sample point and quotients with the same log size
func (f *FriVerifier) FriQuotientEvaluations2(
	sampledValues [][][]m31.QM31,
	sampledPoints components.TreeMaskPoints,
	queries [][]frontend.Variable,
	queriedValues [][]m31.M31,
	randomCoeff m31.QM31,
	circuitData variables.CircuitData,
) [][]m31.QM31 {
	// compute the orvall maximum number of columns for a log size
	maxNColumns := 0
	for i := 0; i < 32; i++ {
		nColumns := 0
		for treeIndex := range len(circuitData.ColumnLogSizes) {
			nColumns += circuitData.NColumnsPerLogSize[treeIndex][i]
		}
		if nColumns > maxNColumns {
			maxNColumns = nColumns
		}
	}
	fmt.Printf("xd1\n")
	// precompute randomCoeff powers
	randomCoeffPowers := make([]m31.QM31, maxNColumns+1)
	randomCoeffPowers[0] = f.qm31Chip.One()
	for i := 1; i < maxNColumns+1; i++ {
		randomCoeffPowers[i] = f.qm31Chip.Mul(randomCoeffPowers[i-1], randomCoeff)
	}
	fmt.Printf("xd2\n")

	// Merge sampled values and sampled points into samples (table of SampleData)
	// This is not a map because order matters when iterating
	// dim-1 (log size): samplesByLogSize groups all columns from all trees per log size
	// dim-2 (point): samplesByLogSize groups sampled values of columns of same log size by sample point
	// dim-3 (samples)
	samplesByLogSize := make([][][]SampleData, 32)
	for i := range samplesByLogSize {
		samplesByLogSize[i] = make([][]SampleData, 0)
	}
	fmt.Printf("xd3\n")

	columnIndexes := make([]int, 32)
	for treeIndex, tree := range sampledPoints {
		for columnIndex, column := range tree {
			logSize := circuitData.ColumnLogSizes[treeIndex][columnIndex] + 1
			for pointIndex, point := range column {
				for range len(column) - len(samplesByLogSize[logSize]) {
					samplesByLogSize[logSize] = append(samplesByLogSize[logSize], make([]SampleData, 0))
				}
				// when 2 points are sampled the order is [pointNegOne, point], this contrasts with the single-sampled points order ([point])
				// using a map would require some encoding/decoding of the points which are just handles and not usable as keys
				alpha := randomCoeffPowers[len(samplesByLogSize[logSize][len(column)-pointIndex-1])+1]
				sampledValue := sampledValues[treeIndex][columnIndex][pointIndex]
				lineCoefficients := GetLineCoefficients(f.qm31Chip, point, sampledValue, alpha)
				samplesByLogSize[logSize][len(column)-pointIndex-1] = append(samplesByLogSize[logSize][len(column)-pointIndex-1], SampleData{
					point:            point,
					columnIndex:      columnIndexes[logSize],
					value:            sampledValue,
					lineCoefficients: lineCoefficients,
				})
			}
			columnIndexes[logSize]++
		}
	}
	fmt.Printf("xd4\n")

	// evaluate the quotient at each query position for each log size
	quotientEvaluations := make([][]m31.QM31, 0)
	queriedValuesPointer := make([]int, len(circuitData.ColumnLogSizes))
	for _, logSize := range circuitData.ColumnBounds {
		fmt.Printf("xd41\n")
		fmt.Printf("logSize = %d\n", logSize)

		samples := samplesByLogSize[logSize]
		circleDomain := circle.NewCanonicCoset(f.circleChip, frontend.Variable(logSize)).CircleDomain()
		layerQuotientEvaluations := make([]m31.QM31, 0)
		for _, queryPosition := range queries[logSize] {
			fmt.Printf("xd42\n")
			fmt.Printf("logSize = %d, queryPosition = %v\n", logSize, queryPosition)
			bitReversedQueryPosition := reverseBitIndex(f.api, f.uapi, queryPosition, logSize)
			domainPoint := circleDomain.At(bitReversedQueryPosition)
			// get flattened (over trees) queried values at query position
			valuesAtQueryPosition := make([]m31.M31, 0)
			for treeIndex := range len(circuitData.ColumnLogSizes) {
				fmt.Printf("xd43\n")
				nColumns := circuitData.NColumnsPerLogSize[treeIndex][logSize-1]
				fmt.Printf("N columns = %v\n", nColumns)

				valuesAtQueryPosition = append(valuesAtQueryPosition, queriedValues[treeIndex][queriedValuesPointer[treeIndex]:queriedValuesPointer[treeIndex]+nColumns]...)
				queriedValuesPointer[treeIndex] += nColumns
			}
			// evaluate the quotient at the query position for the given log size
			layerQuotientEvaluations = append(layerQuotientEvaluations, f.quotientEvaluation(samples, valuesAtQueryPosition, domainPoint, randomCoeffPowers))
		}
		quotientEvaluations = append(quotientEvaluations, layerQuotientEvaluations)
	}
	fmt.Printf("xd5\n")

	return quotientEvaluations
}

// Verify verifies the FRI proof for the given queries and evaluations
func (f *FriVerifier) Verify(queries [][]frontend.Variable, evaluations []logderivlookup.Table) {
	firstLayerEvaluations := f.verifyFirstLayer(queries, evaluations)

	// Print firstLayerEvaluations in readable format
	fmt.Printf("firstLayerEvaluations (%d columns):\n", len(firstLayerEvaluations))
	for colIdx, col := range firstLayerEvaluations {
		fmt.Printf("  Column %d: %d evaluations\n", colIdx, len(col.evals))
		for evalIdx, eval := range col.evals {
			fmt.Printf("    [%d] queryInitial=%v, evals=[", evalIdx, col.queryInitials[evalIdx])
			for pairIdx, qm31Val := range eval {
				components := qm31Val.Components()
				fmt.Printf("{%v %v %v %v}", components[0], components[1], components[2], components[3])
				if pairIdx < len(eval)-1 {
					fmt.Printf(", ")
				}
			}
			fmt.Printf("]\n")
		}
	}
	fmt.Printf("Queries:%d\n", queries)
	// Verify inner layers
	lastEvaluations := f.verifyInnerLayers(queries, firstLayerEvaluations)
	fmt.Printf("lastEvaluations from inner layers: %v evaluations\n", lastEvaluations)

	lastLayerQueries := f.getLastLayerQueries(queries[1])
	f.verifyLastLayer(lastEvaluations, lastLayerQueries)

}

// FriQuotientEvaluations evaluates the FRI quotients
func (f *FriVerifier) FriQuotientEvaluations(
	sampledValues [][][]m31.QM31,
	sampledPoints components.TreeMaskPoints,
	queries [][]frontend.Variable,
	queriedValues [][]m31.M31,
	randomCoeff m31.QM31,
) [][]m31.QM31 {
	maxNColumns := 0
	for i := 0; i < 32; i++ {
		nColumns := 0
		for _, treeLogSizes := range f.treeColumnLogSizes {
			for _, logSize := range treeLogSizes {
				if logSize == i {
					nColumns++
				}
			}
		}
		if nColumns > maxNColumns {
			maxNColumns = nColumns
		}
	}
	fmt.Printf("MaxNColumns = %d\n", maxNColumns)

	// precompute randomCoeff powers
	randomCoeffPowers := make([]m31.QM31, maxNColumns+1)
	randomCoeffPowers[0] = f.qm31Chip.One()
	for i := 1; i < maxNColumns+1; i++ {
		randomCoeffPowers[i] = f.qm31Chip.Mul(randomCoeffPowers[i-1], randomCoeff)
	}

	if maxNColumns >= 2 {
		fmt.Printf("Random coeff powers[2] = %v\n", randomCoeffPowers[2])
	}

	samplesByLogSize := make([][][]SampleData, 32)
	for i := range samplesByLogSize {
		samplesByLogSize[i] = make([][]SampleData, 0)
	}
	columnIndexes := make([]int, 32)
	for treeIndex, tree := range sampledPoints {
		for columnIndex, column := range tree {
			commitmentLogSize := f.treeColumnLogSizes[treeIndex][columnIndex]
			for pointIndex, point := range column {
				for range len(column) - len(samplesByLogSize[commitmentLogSize]) {
					samplesByLogSize[commitmentLogSize] = append(samplesByLogSize[commitmentLogSize], make([]SampleData, 0))
				}
				alphaIndex := len(samplesByLogSize[commitmentLogSize][len(column)-pointIndex-1])
				alpha := randomCoeffPowers[alphaIndex]
				sampledValue := sampledValues[treeIndex][columnIndex][pointIndex]
				lineCoefficients := GetLineCoefficients(f.qm31Chip, point, sampledValue, alpha)
				samplesByLogSize[commitmentLogSize][len(column)-pointIndex-1] = append(samplesByLogSize[commitmentLogSize][len(column)-pointIndex-1], SampleData{
					point:            point,
					columnIndex:      columnIndexes[commitmentLogSize],
					value:            sampledValue,
					lineCoefficients: lineCoefficients,
				})
			}
			columnIndexes[commitmentLogSize]++
		}
	}

	quotientEvaluations := make([][]m31.QM31, 0)
	queriedValuesPointer := make([]int, len(f.treeColumnLogSizes))

	// Get unique commitment log sizes (sorted descending)
	// f.treeColumnLogSizes contains commitment domain log sizes
	uniqueCommitmentSizes := make(map[int]struct{})
	for _, treeSizes := range f.treeColumnLogSizes {
		for _, commitmentSize := range treeSizes {
			uniqueCommitmentSizes[commitmentSize] = struct{}{}
		}
	}

	commitmentSizes := make([]int, 0, len(uniqueCommitmentSizes))
	for size := range uniqueCommitmentSizes {
		commitmentSizes = append(commitmentSizes, size)
	}
	// Sort descending
	for i := 0; i < len(commitmentSizes); i++ {
		for j := i + 1; j < len(commitmentSizes); j++ {
			if commitmentSizes[i] < commitmentSizes[j] {
				commitmentSizes[i], commitmentSizes[j] = commitmentSizes[j], commitmentSizes[i]
			}
		}
	}

	// Process queries for each commitment log size
	for _, commitmentLogSize := range commitmentSizes {
		samples := samplesByLogSize[commitmentLogSize]

		circleDomain := circle.NewCanonicCoset(f.circleChip, frontend.Variable(commitmentLogSize)).CircleDomain()
		layerQuotientEvaluations := make([]m31.QM31, 0)

		// Iterate queries for this commitment log size
		for _, queryPosition := range queries[commitmentLogSize] {
			bitReversedQueryPosition := reverseBitIndex(f.api, f.uapi, queryPosition, commitmentLogSize)
			domainPoint := circleDomain.At(bitReversedQueryPosition)

			valuesAtQueryPosition := make([]m31.M31, 0)
			for treeIndex, treeLogSizes := range f.treeColumnLogSizes {
				// treeLogSizes contains commitment domain log sizes, match them directly
				nColumns := 0
				for _, ls := range treeLogSizes {
					if ls == commitmentLogSize {
						nColumns++
					}
				}
				if nColumns > 0 {
					extractedValues := queriedValues[treeIndex][queriedValuesPointer[treeIndex] : queriedValuesPointer[treeIndex]+nColumns]
					valuesAtQueryPosition = append(valuesAtQueryPosition, extractedValues...)
				}
				queriedValuesPointer[treeIndex] += nColumns
			}

			result := f.quotientEvaluation(samples, valuesAtQueryPosition, domainPoint, randomCoeffPowers)
			layerQuotientEvaluations = append(layerQuotientEvaluations, result)
		}
		quotientEvaluations = append(quotientEvaluations, layerQuotientEvaluations)
	}

	return quotientEvaluations
}

// SampleData and GetLineCoefficients ...
type SampleData struct {
	point            circle.Point
	columnIndex      int
	value            m31.QM31
	lineCoefficients [3]m31.QM31
}

func GetLineCoefficients(qm31Chip *m31.QM31Chip, samplePoint circle.Point, sampledValue m31.QM31, alpha m31.QM31) [3]m31.QM31 {
	a := qm31Chip.Sub(qm31Chip.ComplexConjugate(sampledValue), sampledValue)
	c := qm31Chip.Sub(qm31Chip.ComplexConjugate(samplePoint.Y), samplePoint.Y)
	b := qm31Chip.Sub(qm31Chip.Mul(sampledValue, c), qm31Chip.Mul(a, samplePoint.Y))
	return [3]m31.QM31{qm31Chip.Mul(alpha, a), qm31Chip.Mul(alpha, b), qm31Chip.Mul(alpha, c)}
}

func (f *FriVerifier) quotientEvaluation(samples [][]SampleData, valuesAtQueryPosition []m31.M31, domainPoint circle.BasePoint, randomCoeffPowers []m31.QM31) m31.QM31 {
	quotientEvaluation := f.qm31Chip.Zero()
	for _, samplesData := range samples {
		point := samplesData[0].point

		samplePointRX := m31.CM31{Real: point.X.AReal, Imag: point.X.AImag}
		samplePointRY := m31.CM31{Real: point.Y.AReal, Imag: point.Y.AImag}
		samplePointIX := m31.CM31{Real: point.X.BReal, Imag: point.X.BImag}
		samplePointIY := m31.CM31{Real: point.Y.BReal, Imag: point.Y.BImag}
		denominator := f.qm31Chip.CmSub(
			f.qm31Chip.CmMul(
				f.qm31Chip.CmSubM31(
					samplePointRX,
					domainPoint.X,
				),
				samplePointIY,
			),
			f.qm31Chip.CmMul(
				f.qm31Chip.CmSubM31(
					samplePointRY,
					domainPoint.Y,
				),
				samplePointIX,
			),
		)
		denominatorInverse := f.qm31Chip.CM31Inverse(denominator)

		numerator := f.qm31Chip.Zero()
		for _, sampleData := range samplesData {
			a := sampleData.lineCoefficients[0]
			b := sampleData.lineCoefficients[1]
			c := sampleData.lineCoefficients[2]
			columnIdx := sampleData.columnIndex

			if columnIdx >= len(valuesAtQueryPosition) {
				continue
			}

			queryValue := valuesAtQueryPosition[columnIdx]
			value := f.qm31Chip.MulM31(c, queryValue)
			linearTerm := f.qm31Chip.Add(f.qm31Chip.MulM31(a, domainPoint.Y), b)
			term := f.qm31Chip.Sub(value, linearTerm)
			numerator = f.qm31Chip.Add(numerator, term)
		}

		pointCoeff := randomCoeffPowers[len(samplesData)]
		frac := f.qm31Chip.MulCM31(numerator, denominatorInverse)
		quotientEvaluation = f.qm31Chip.Add(f.qm31Chip.Mul(quotientEvaluation, pointCoeff), frac)
	}
	return quotientEvaluation
}

// First Layer
type FriFirstLayerVerifier struct {
	columnBounds            []frontend.Variable
	columnCommitmentDomains []circle.CircleDomain
	proof                   variables.FriLayerProof
	foldingAlpha            m31.QM31
}

type SparseEvaluations struct {
	queryInitials []uints.U32
	evals         [][2]m31.QM31
}

func (f *FriVerifier) verifyFirstLayer(queries [][]frontend.Variable, evaluations []logderivlookup.Table) []SparseEvaluations {
	sparseEvaluationsFlattened := make([]m31.M31, 0)
	sparseEvaluations := make([]SparseEvaluations, 0)
	previousFriWitnessIndex := frontend.Variable(0)

	columnBoundsIndex := 0
	logBlowup := f.friConfig.LogBlowupFactor

	// Iterate over columns in descending order by commitment domain size
	// bounds are degree bounds; commitment_log_size = bound + log_blowup_factor
	for columnBoundsIndex < len(f.bounds) {
		bound := f.bounds[columnBoundsIndex]
		commitmentLogSize := bound + logBlowup

		fmt.Printf("DEBUG verifyFirstLayer: columnIdx=%d, bound=%d, commitmentLogSize=%d\n",
			columnBoundsIndex, bound, commitmentLogSize)

		var layerSparseEvaluationsFlattened []m31.M31
		var sparseEvaluation SparseEvaluations
		var friWitnessIndex frontend.Variable

		// And queriesParent is at folded domain (size 2^(commitmentLogSize-1))
		layerSparseEvaluationsFlattened, sparseEvaluation, friWitnessIndex = f.RebuildEvals(
			evaluations[columnBoundsIndex],
			f.FirstLayerVerifier.proof.FriWitness,
			previousFriWitnessIndex,
			queries[commitmentLogSize],   // queries on commitment domain
			queries[commitmentLogSize-1], // queries on parent (folded/smaller) domain
			commitmentLogSize,
		)
		previousFriWitnessIndex = friWitnessIndex

		sparseEvaluations = append(sparseEvaluations, sparseEvaluation)
		sparseEvaluationsFlattened = append(sparseEvaluationsFlattened, layerSparseEvaluationsFlattened...)

		columnBoundsIndex++
	}

	columnLogSizes := make([]frontend.Variable, 0)
	for _, domain := range f.FirstLayerVerifier.columnCommitmentDomains {
		columnLogSizes = append(columnLogSizes, f.api.Sub(domain.LogSize(), frontend.Variable(1)))
		columnLogSizes = append(columnLogSizes, f.api.Sub(domain.LogSize(), frontend.Variable(1)))
		columnLogSizes = append(columnLogSizes, f.api.Sub(domain.LogSize(), frontend.Variable(1)))
		columnLogSizes = append(columnLogSizes, f.api.Sub(domain.LogSize(), frontend.Variable(1)))
	}

	nColumnsPerLogSize := make([]int, 32)
	for i := range f.bounds {
		commitmentLogSize := f.bounds[i] + logBlowup
		nColumnsPerLogSize[commitmentLogSize] = 4
	}

	// Verify Merkle decommitment
	merkleVerifier := NewMerkleVerifier(f.api, f.uapi, f.FirstLayerVerifier.proof.Commitment, columnLogSizes, nColumnsPerLogSize)
	// Pass queries slice directly
	merkleVerifier.Verify(queries, sparseEvaluationsFlattened, f.FirstLayerVerifier.proof.Decommitment)

	return sparseEvaluations
}

// Inner Layers
type FriInnerLayerVerifier struct {
	degreeBound  frontend.Variable
	domain       circle.LineDomain
	foldingAlpha m31.QM31
	layerIndex   int
	proof        variables.FriLayerProof
}

func (f *FriVerifier) verifyInnerLayers(queries [][]frontend.Variable, firstLayerEvaluations []SparseEvaluations) []m31.QM31 {
	columnBoundsIndex := 0
	previousAlpha := f.FirstLayerVerifier.foldingAlpha
	maxLogSize := f.bounds[0] - 2

	fmt.Printf("DEBUG: bounds=%v maxLogSize=%d\n", f.bounds, maxLogSize)
	fmt.Printf("DEBUG: firstLayerEvaluations len=%d\n", len(firstLayerEvaluations))

	// The first inner layer processes folded evaluations from the first column
	// Use the number of evaluations from the first column
	nQueriesForFirstInnerLayer := len(firstLayerEvaluations[0].evals)
	fmt.Printf("DEBUG: nQueriesForFirstInnerLayer=%d (from firstLayerEvaluations[0])\n", nQueriesForFirstInnerLayer)
	currentLayerEvals := make([]m31.QM31, nQueriesForFirstInnerLayer)
	for i := range currentLayerEvals {
		currentLayerEvals[i] = f.qm31Chip.Zero()
	}

	for logSize := maxLogSize; logSize >= 2; logSize-- {
		layerIndex := maxLogSize - logSize
		if layerIndex >= len(f.InnerLayerVerifiers) {
			fmt.Printf("DEBUG: Stopping verifyInnerLayers at logSize=%d. layerIndex=%d exceeds len=%d\n", logSize, layerIndex, len(f.InnerLayerVerifiers))
			break
		}

		innerLayerVerifier := f.InnerLayerVerifiers[layerIndex]

		fmt.Printf("DEBUG: logSize=%d columnBoundsIndex=%d\n", logSize, columnBoundsIndex)

		if columnBoundsIndex < len(f.FirstLayerVerifier.columnBounds) && f.bounds[columnBoundsIndex]-2 == logSize {
			foldedColumnEvals := make([]m31.QM31, 0)

			fmt.Printf("DEBUG: Processing FRI answer for logSize %d. columnBoundsIndex=%d. evals len=%d. queryInitials len=%d\n", logSize, columnBoundsIndex, len(firstLayerEvaluations[columnBoundsIndex].evals), len(firstLayerEvaluations[columnBoundsIndex].queryInitials))

			for i, eval := range firstLayerEvaluations[columnBoundsIndex].evals {
				fmt.Printf("DEBUG: accessing queryInitial index %d\n", i)
				queryInitial := firstLayerEvaluations[columnBoundsIndex].queryInitials[i]
				columnDomain := f.FirstLayerVerifier.columnCommitmentDomains[columnBoundsIndex]
				P := columnDomain.IndexAt(queryInitial).Point()
				h0 := eval[0]
				h1 := eval[1]
				evenPart := f.qm31Chip.Add(h0, h1)
				inversePy, _ := f.m31Chip.Inverse(P.Y)
				oddPart := f.qm31Chip.MulM31(f.qm31Chip.Sub(h0, h1), inversePy)
				folded := f.qm31Chip.Add(evenPart, f.qm31Chip.Mul(previousAlpha, oddPart))
				foldedColumnEvals = append(foldedColumnEvals, folded)
			}
			columnBoundsIndex++

			previousAlphaSq := f.qm31Chip.Mul(previousAlpha, previousAlpha)
			for i, eval := range foldedColumnEvals {
				currentLayerEvals[i] = f.qm31Chip.Mul(currentLayerEvals[i], previousAlphaSq)
				currentLayerEvals[i] = f.qm31Chip.Add(currentLayerEvals[i], eval)
			}
		}

		encodedCurrentLayerEvalsLookup := logderivlookup.New(f.api)
		for _, eval := range currentLayerEvals {
			encodedCurrentLayerEvalsLookup.Insert(f.qm31Chip.EncodeNative(eval))
		}
		encodedCurrentLayerEvalsLookup.Insert(frontend.Variable(1 << 32))

		columnLogSizes := []frontend.Variable{frontend.Variable(logSize), frontend.Variable(logSize), frontend.Variable(logSize), frontend.Variable(logSize)}

		// Removed ignored return value
		sparseEvaluationsFlattened, sparseEvaluation, _ := f.RebuildEvals(
			encodedCurrentLayerEvalsLookup,
			f.InnerLayerVerifiers[innerLayerVerifier.layerIndex].proof.FriWitness,
			0,
			queries[logSize+1],
			queries[logSize],
			logSize+1,
		)
		fmt.Printf("DEBUG: RebuildEvals done for logSize=%d, sparseEvaluation evals = %v\n", logSize, sparseEvaluation.evals)

		nColumnsPerLogSize := make([]int, 32)
		nColumnsPerLogSize[logSize+1] = 4

		merkleVerifier := NewMerkleVerifier(f.api, f.uapi, f.InnerLayerVerifiers[innerLayerVerifier.layerIndex].proof.Commitment, columnLogSizes, nColumnsPerLogSize)
		merkleVerifier.Verify(queries, sparseEvaluationsFlattened, f.InnerLayerVerifiers[innerLayerVerifier.layerIndex].proof.Decommitment)

		currentLayerEvals = make([]m31.QM31, len(queries[logSize]))

		for i, eval := range sparseEvaluation.evals {
			fmt.Printf("DEBUG: Second loop logSize=%d. i=%d. queryInitials len=%d\n", logSize, i, len(sparseEvaluation.queryInitials))
			queryInitial := sparseEvaluation.queryInitials[i]
			domain := innerLayerVerifier.domain.Coset()
			queryInitialLE := uints.U32{queryInitial[3], queryInitial[2], queryInitial[1], queryInitial[0]}
			P := domain.IndexAt(queryInitialLE).Point()
			h0 := eval[0]
			h1 := eval[1]

			evenPart := f.qm31Chip.Add(h0, h1)

			inversePx, _ := f.m31Chip.Inverse(P.X)
			oddPart := f.qm31Chip.MulM31(f.qm31Chip.Sub(h0, h1), inversePx)
			folded := f.qm31Chip.Add(evenPart, f.qm31Chip.Mul(innerLayerVerifier.foldingAlpha, oddPart))
			currentLayerEvals[i] = folded
		}

		previousAlpha = innerLayerVerifier.foldingAlpha
	}

	return currentLayerEvals
}

func (f *FriVerifier) verifyLastLayer(lastEvaluations []m31.QM31, queryPositions []uints.U32) {
	domain := f.lastLayerDomain.Coset()
	for i, eval := range lastEvaluations {
		queryInitialLE := uints.U32{queryPositions[i][3], queryPositions[i][2], queryPositions[i][1], queryPositions[i][0]}
		domainPointM31 := domain.IndexAt(queryInitialLE).Point().X
		x := m31.NewQM31FromM31(domainPointM31)
		expectedEval := f.LastLayerPoly.EvalAt(f.qm31Chip, x)
		f.qm31Chip.AssertEqual(eval, expectedEval)
	}
}

func (f *FriVerifier) getLastLayerQueries(queries []frontend.Variable) []uints.U32 {
	qU32 := make([]uints.U32, len(queries))
	for i, q := range queries {
		qU32[i] = f.uapi.ValueOf(q)
	}
	return qU32
}

func (f *FriVerifier) RebuildEvals(
	evalAtQueries logderivlookup.Table,
	witnessEvals []m31.QM31,
	previousFriWitnessIndex frontend.Variable,
	queriesLayer []frontend.Variable,
	queriesParent []frontend.Variable,
	logSize int,
) ([]m31.M31, SparseEvaluations, frontend.Variable) { // Removed Table return
	fmt.Printf("DEBUG RebuildEvals: logSize=%d, queriesLayer len=%d, queriesParent len=%d\n", logSize, len(queriesLayer), len(queriesParent))

	pairedEvalsFlattened := make([]m31.M31, 0)
	pairedEvals := make([][2]m31.QM31, 0)
	queryInitials := make([]uints.U32, 0)
	witnessIndex := previousFriWitnessIndex

	// Handle empty queries case
	if len(queriesLayer) == 0 {
		fmt.Printf("DEBUG RebuildEvals: No queriesLayer, returning empty\n")
		return pairedEvalsFlattened, SparseEvaluations{
			queryInitials: queryInitials,
			evals:         pairedEvals,
		}, witnessIndex
	}

	nParents := len(queriesParent)
	var branching []frontend.Variable
	if nParents > 0 {
		inputs := append(queriesParent, queriesLayer...)
		var err error
		branching, err = f.api.Compiler().NewHint(utils.QueriesBranchingHint, nParents, inputs...)
		if err != nil {
			panic(err)
		}
	} else {
		// No parent queries - this happens for smaller commitment domains
		// In this case, we process all queries directly without branching
		fmt.Printf("DEBUG RebuildEvals: No parent queries, processing all layer queries directly\n")
	}

	childIdx := frontend.Variable(0)

	queriesLayerTable := logderivlookup.New(f.api)
	for _, q := range queriesLayer {
		queriesLayerTable.Insert(q)
	}
	queriesLayerTable.Insert(frontend.Variable(1 << 32))
	queriesLayerTable.Insert(frontend.Variable(1 << 32))

	witnessTable := logderivlookup.New(f.api)
	for _, w := range witnessEvals {
		witnessTable.Insert(f.qm31Chip.EncodeNative(w))
	}
	witnessTable.Insert(frontend.Variable(0))

	// Handle two cases: with parent queries (using branching) or without
	if nParents > 0 {
		// Normal case: process using parent queries and branching hint
		for i, parentQ := range queriesParent {
			isDummy := f.api.IsZero(f.api.Sub(parentQ, 1<<32))
			branchCode := branching[i]

			bits := f.api.ToBinary(branchCode, 2)
			leftPresent := bits[0]
			rightPresent := bits[1]

			leftPresent = f.api.Select(isDummy, 0, leftPresent)
			rightPresent = f.api.Select(isDummy, 0, rightPresent)

			parentQBinary := f.api.ToBinary(parentQ, 32)
			leftChild := f.api.FromBinary(append([]frontend.Variable{0}, parentQBinary...)...)
			rightChild := f.api.Add(leftChild, 1)

			qLeft := queriesLayerTable.Lookup(childIdx)[0]
			f.api.AssertIsEqual(f.api.Select(leftPresent, qLeft, leftChild), leftChild)

			idxRight := f.api.Add(childIdx, leftPresent)
			qRight := queriesLayerTable.Lookup(idxRight)[0]
			f.api.AssertIsEqual(f.api.Select(rightPresent, qRight, rightChild), rightChild)

			eLeftCalc := evalAtQueries.Lookup(childIdx)[0]
			w0 := witnessTable.Lookup(witnessIndex)[0]
			eLeftEncoded := f.api.Select(leftPresent, eLeftCalc, w0)

			witnessOffset := f.api.Sub(1, leftPresent)
			idxWRight := f.api.Add(witnessIndex, witnessOffset)
			wRight := witnessTable.Lookup(idxWRight)[0]
			eRightCalc := evalAtQueries.Lookup(idxRight)[0]
			eRightEncoded := f.api.Select(rightPresent, eRightCalc, wRight)

			childIdx = f.api.Add(childIdx, f.api.Add(leftPresent, rightPresent))
			witnessConsumed := f.api.Add(f.api.Sub(1, leftPresent), f.api.Sub(1, rightPresent))
			witnessIndex = f.api.Add(witnessIndex, witnessConsumed)

			eLeft := f.qm31Chip.DecodeNative(eLeftEncoded)
			eRight := f.qm31Chip.DecodeNative(eRightEncoded)

			pairedEvals = append(pairedEvals, [2]m31.QM31{eLeft, eRight})

			leftEvalComponents := eLeft.Components()
			pairedEvalsFlattened = append(pairedEvalsFlattened, leftEvalComponents[0], leftEvalComponents[1], leftEvalComponents[2], leftEvalComponents[3])
			rightEvalComponents := eRight.Components()
			pairedEvalsFlattened = append(pairedEvalsFlattened, rightEvalComponents[0], rightEvalComponents[1], rightEvalComponents[2], rightEvalComponents[3])

			queryInitials = append(queryInitials, reverseBitIndex(f.api, f.uapi, leftChild, logSize))
		}
	} else {
		// No parent queries: process each query directly as a pair
		// Each query becomes a left position, and we need witness for right position
		for i, query := range queriesLayer {
			// Calculate left and right positions for this subset
			queryBits := f.api.ToBinary(query, 32)
			// Clear lowest bit to get left position (subset start)
			leftBits := queryBits[:31]
			leftBits = append(leftBits, frontend.Variable(0))
			leftChild := f.api.FromBinary(leftBits...)

			// Check if query is left or right
			isLeft := f.api.IsZero(queryBits[0]) // If lowest bit is 0, it's left

			// Get evaluation for this query
			eQueryEncoded := evalAtQueries.Lookup(frontend.Variable(i))[0]

			// Get witness for the sibling position
			eSiblingEncoded := witnessTable.Lookup(witnessIndex)[0]
			witnessIndex = f.api.Add(witnessIndex, 1)

			// Determine left and right evaluations based on whether query is left or right
			eLeftEncoded := f.api.Select(isLeft, eQueryEncoded, eSiblingEncoded)
			eRightEncoded := f.api.Select(isLeft, eSiblingEncoded, eQueryEncoded)

			eLeft := f.qm31Chip.DecodeNative(eLeftEncoded)
			eRight := f.qm31Chip.DecodeNative(eRightEncoded)

			pairedEvals = append(pairedEvals, [2]m31.QM31{eLeft, eRight})

			leftEvalComponents := eLeft.Components()
			pairedEvalsFlattened = append(pairedEvalsFlattened, leftEvalComponents[0], leftEvalComponents[1], leftEvalComponents[2], leftEvalComponents[3])
			rightEvalComponents := eRight.Components()
			pairedEvalsFlattened = append(pairedEvalsFlattened, rightEvalComponents[0], rightEvalComponents[1], rightEvalComponents[2], rightEvalComponents[3])

			queryInitials = append(queryInitials, reverseBitIndex(f.api, f.uapi, leftChild, logSize))
		}
	}

	return pairedEvalsFlattened, SparseEvaluations{queryInitials: queryInitials, evals: pairedEvals}, witnessIndex
}

func convertTablesToSlices(api frontend.API, tables []logderivlookup.Table, maxLogSize int) [][]frontend.Variable {
	// Not needed anymore
	return nil
}

func reverseBitIndex(api frontend.API, uapi *uints.BinaryField[uints.U32], n frontend.Variable, logSize int) uints.U32 {
	nBits := bits.ToBinary(api, n, bits.WithNbDigits(32))
	reversedBits := make([]frontend.Variable, 32)
	for i := 0; i < 32; i++ {
		reversedBits[i] = nBits[32-(i+1)]
	}
	nReversedNative := bits.FromBinary(api, reversedBits)
	nReversedBytes, err := conversion.NativeToBytes(api, nReversedNative)
	if err != nil {
		panic(err)
	}
	nReversed := uints.U32{nReversedBytes[len(nReversedBytes)-1], nReversedBytes[len(nReversedBytes)-2], nReversedBytes[len(nReversedBytes)-3], nReversedBytes[len(nReversedBytes)-4]}
	result := uapi.Rshift(nReversed, 32-logSize)
	return uints.U32{result[3], result[2], result[1], result[0]}
}
