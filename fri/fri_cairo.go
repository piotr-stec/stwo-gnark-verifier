package fri

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/HerodotusDev/stwo-gnark-verifier/utils"
	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/consensys/gnark/std/math/uints"
)

// Verify verifies the FRI proof for the given queries and evaluations
func (f *FriVerifier) Verify2(queries []logderivlookup.Table, evaluations []logderivlookup.Table, shape variables.CircuitData) {
	firstLayerEvaluations := f.verifyFirstLayer2(queries, evaluations, shape)

	lastQueries, lastEvaluations := f.verifyInnerLayers2(queries, firstLayerEvaluations, shape)

	f.verifyLastLayer2(lastQueries, lastEvaluations, shape)
}

// ╔══════════════════════════════════╗
// ║           FRI Quotients          ║
// ╚══════════════════════════════════╝

func (f *FriVerifier) verifyFirstLayer2(queries []logderivlookup.Table, evaluations []logderivlookup.Table, circuitData variables.CircuitData) []SparseEvaluations {
	
	// return sparseEvaluations
	// compute the decommitment positions (queries and their siblings dedupped) and build the matching decommitments values
	decommitmentPositions := make([]logderivlookup.Table, 32)
	sparseEvaluationsFlattened := make([]m31.M31, 0)
	sparseEvaluations := make([]SparseEvaluations, 0)
	previousFriWitnessIndex := 0

	columnBoundsIndex := 0
	maxLogSize := circuitData.ColumnBounds[0]

	queriesShape := make([]int, 32)

	// build the merkle tree decommitment for the fri answers
	// for each layer there either is FRI answers or not
	// if there are FRI answers, we compute the decommitment positions and the sparse evaluations from the FRI answers
	// if there are no FRI answers, we just fold the previous layer queries
	for logSize := maxLogSize; logSize >= 0; logSize-- {
		if columnBoundsIndex < len(circuitData.ColumnBounds) && logSize == circuitData.ColumnBounds[columnBoundsIndex] {
			layerQueries := queries[logSize]
			// compute local data
			layerDecommitmentPositions, layerSparseEvaluationsFlattened, sparseEvaluation, friWitnessIndex := f.computeDecommitmentPositionsAndRebuildEvals(
				layerQueries,
				evaluations[columnBoundsIndex],
				f.FirstLayerVerifier.proof.FriWitness,
				previousFriWitnessIndex,
				circuitData.DedupedQueriesShape[logSize-1],
				logSize, circuitData,
			)
			previousFriWitnessIndex = friWitnessIndex

			// dummy values to simulate the unused children queries of the last query (if it is on the right) of a layer
			layerDecommitmentPositions.Insert(frontend.Variable(1 << 32))
			layerDecommitmentPositions.Insert(frontend.Variable(1 << 32))

			// update global data
			decommitmentPositions[logSize] = layerDecommitmentPositions
			sparseEvaluations = append(sparseEvaluations, sparseEvaluation)
			sparseEvaluationsFlattened = append(sparseEvaluationsFlattened, layerSparseEvaluationsFlattened...)
			// the trick here is to note that when building all the pairs of queries in a layer, we end up with
			// 2 times the number of queries in the next layer
			queriesShape[logSize] = 2 * circuitData.DedupedQueriesShape[logSize-1]
			columnBoundsIndex++
		} else {
			// if there are no FRI answers, we just fold the previous layer queries
			// convert the lookup table to a slice of frontend.Variable
			previousLayerQueriesLookup := decommitmentPositions[logSize+1]
			previousLayerQueries := make([]frontend.Variable, 0)
			nQueriesPreviousLayer := 0
			// if the previous layer contains fri answers
			if logSize+1 == circuitData.ColumnBounds[columnBoundsIndex-1] {
				nQueriesPreviousLayer = 2 * circuitData.DedupedQueriesShape[logSize]
			} else {
				nQueriesPreviousLayer = circuitData.DedupedQueriesShape[logSize+1]
			}
			for i := 0; i < nQueriesPreviousLayer; i++ {
				previousLayerQueries = append(previousLayerQueries, previousLayerQueriesLookup.Lookup(frontend.Variable(i))[0])
			}

			// fold the previous layer queries
			layerQueries := utils.FoldQueries(f.api, previousLayerQueries, circuitData.DedupedQueriesShape[logSize])

			// convert the slice of frontend.Variable to a lookup table
			layerQueriesLookup := logderivlookup.New(f.api)
			for _, query := range layerQueries {
				layerQueriesLookup.Insert(query)
			}
			layerQueriesLookup.Insert(frontend.Variable(1 << 32))
			layerQueriesLookup.Insert(frontend.Variable(1 << 32))

			queriesShape[logSize] = circuitData.DedupedQueriesShape[logSize]
			decommitmentPositions[logSize] = layerQueriesLookup
		}
		// all lookup tables need at least one query, this makes sure they all get one (root doesn't otherwise)
		_ = decommitmentPositions[logSize].Lookup(0)

	}


	// build the column log sizes (1 flattened QM31 column yields 4 M31 columns)
	columnLogSizes := make([]frontend.Variable, 0)
	for _, columnCommitmentDomain := range f.FirstLayerVerifier.columnCommitmentDomains {
		columnLogSizes = append(columnLogSizes, f.api.Sub(columnCommitmentDomain.LogSize(), frontend.Variable(1)))
		columnLogSizes = append(columnLogSizes, f.api.Sub(columnCommitmentDomain.LogSize(), frontend.Variable(1)))
		columnLogSizes = append(columnLogSizes, f.api.Sub(columnCommitmentDomain.LogSize(), frontend.Variable(1)))
		columnLogSizes = append(columnLogSizes, f.api.Sub(columnCommitmentDomain.LogSize(), frontend.Variable(1)))
	}

	nColumnsPerLogSize := make([]int, 32)
	for _, logSize := range circuitData.ColumnBounds {
		nColumnsPerLogSize[logSize] = 4
	}

	// verify the merkle decommitment
	merkleVerifier := NewMerkleVerifier(f.api, f.uapi, f.FirstLayerVerifier.proof.Commitment, columnLogSizes, nColumnsPerLogSize)
	firstLayerBranching := circuitData.FriFirstLayerBranching
	if len(firstLayerBranching) == 0 {
		panic("missing FRI first layer branching data")
	}
	merkleVerifier.Verify2(decommitmentPositions, sparseEvaluationsFlattened, f.FirstLayerVerifier.proof.Decommitment, queriesShape, firstLayerBranching)

	return sparseEvaluations
}

// ╔══════════════════════════════════╗
// ║            Inner Layers          ║
// ╚══════════════════════════════════╝

// VerifyInnerLayers verifies the inner layers of a FRI proof
// Returns the final layer queries and their evaluations
func (f *FriVerifier) verifyInnerLayers2(queries []logderivlookup.Table, firstLayerEvaluations []SparseEvaluations, circuitData variables.CircuitData) (logderivlookup.Table, []m31.QM31) {
	columnBoundsIndex := 0
	previousAlpha := f.FirstLayerVerifier.foldingAlpha
	maxLogSize := circuitData.ColumnBounds[0] - 2

	// initialize the current layer evaluations - start with size based on first layer that will be processed
	var currentLayerEvals []m31.QM31
	if len(firstLayerEvaluations) > 0 && len(firstLayerEvaluations[0].evals) > 0 {
		currentLayerEvals = make([]m31.QM31, len(firstLayerEvaluations[0].evals))
		for i := range currentLayerEvals {
			currentLayerEvals[i] = f.qm31Chip.Zero()
		}
	}

	for logSize := maxLogSize; logSize >= 1 && (maxLogSize-logSize) < len(f.InnerLayerVerifiers); logSize-- {
		innerLayerVerifier := f.InnerLayerVerifiers[maxLogSize-logSize]
		// check if we need to fold in fri answers to this layer
		if columnBoundsIndex < len(f.FirstLayerVerifier.columnBounds) && circuitData.ColumnBounds[columnBoundsIndex]-2 == logSize {
			// fold the evaluations from H_i to I_i
			foldedColumnEvals := make([]m31.QM31, 0)

			for i, eval := range firstLayerEvaluations[columnBoundsIndex].evals {

				// queryInitial is the index of (x_i,y_i) in H_i
				queryInitial := firstLayerEvaluations[columnBoundsIndex].queryInitials[i]
				// columnDomain corresponds to the circle domain H_i
				columnDomain := f.FirstLayerVerifier.columnCommitmentDomains[columnBoundsIndex]
				// P is the point (x_i,y_i) in H_i, we only need the y coordinate for folding
				P := columnDomain.IndexAt(queryInitial).Point()
				// Calculate `evenPart` and `oddPart` such that `2h(P) = evenPart + Py * oddPart`.
				h0 := eval[0] // h(P) = h(x_i, y_i)
				h1 := eval[1] // h(-P) = h(x_i, -y_i)
				evenPart := f.qm31Chip.Add(h0, h1)
				inversePy, _ := f.m31Chip.Inverse(P.Y)
				oddPart := f.qm31Chip.MulM31(f.qm31Chip.Sub(h0, h1), inversePy)
				// fold the evaluations with the previous alpha
				folded := f.qm31Chip.Add(evenPart, f.qm31Chip.Mul(previousAlpha, oddPart))
				foldedColumnEvals = append(foldedColumnEvals, folded)
			}
			columnBoundsIndex++

			// build g_i(x_j) from folded column evaluations and folded g_{i-1}
			previousAlphaSq := f.qm31Chip.Mul(previousAlpha, previousAlpha)
			for i, eval := range foldedColumnEvals {
				currentLayerEvals[i] = f.qm31Chip.Mul(currentLayerEvals[i], previousAlphaSq)
				currentLayerEvals[i] = f.qm31Chip.Add(currentLayerEvals[i], eval)
			}
		}

		// encode the g_i(x_j) into a lookup table of frontend.Variables
		encodedCurrentLayerEvalsLookup := logderivlookup.New(f.api)
		for _, eval := range currentLayerEvals {
			encodedCurrentLayerEvalsLookup.Insert(f.qm31Chip.EncodeNative(eval))
		}
		encodedCurrentLayerEvalsLookup.Insert(frontend.Variable(1 << 32))

		// build the column log sizes (1 flattened QM31 column yields 4 M31 columns)
		columnLogSizes := []frontend.Variable{logSize, logSize, logSize, logSize}

		// verify g_i(x_j) decommitments
		layerDecommitmentPositions, sparseEvaluationsFlattened, sparseEvaluation, _ := f.computeDecommitmentPositionsAndRebuildEvals(
			queries[logSize+1],
			encodedCurrentLayerEvalsLookup,
			f.InnerLayerVerifiers[innerLayerVerifier.layerIndex].proof.FriWitness,
			0,
			circuitData.DedupedQueriesShape[logSize],
			logSize+1, circuitData,
		)
		// build the decommitment positions and query shape for merkle decommitment verification
		// the merkle tree is built with just 4 columns on the largest layer
		// so decommitment positions on the largest layer are the paires queries computed in layerDecommitmentPositions
		// then the next layer is the folded queries from the previous layer
		// and the rest of the layers are the regular queries (no pairs) that can be taken from the queries table
		queryShape := make([]int, 32)

		// first layer is layerDecommitmentPositions
		decommitmentPositions := make([]logderivlookup.Table, 32)
		decommitmentPositions[logSize+1] = layerDecommitmentPositions
		queryShape[logSize+1] = 2 * circuitData.DedupedQueriesShape[logSize]

		// fold the previous layer knowing that there are 2*f.circuitData.DedupedQueriesShape[logSize] queries
		previousLayerQueriesLookup := layerDecommitmentPositions
		previousLayerQueries := make([]frontend.Variable, 0)
		for i := 0; i < 2*circuitData.DedupedQueriesShape[logSize]; i++ {
			previousLayerQueries = append(previousLayerQueries, previousLayerQueriesLookup.Lookup(frontend.Variable(i))[0])
		}
		layerQueries := utils.FoldQueries(f.api, previousLayerQueries, circuitData.DedupedQueriesShape[logSize])
		layerQueriesLookup := logderivlookup.New(f.api)
		for _, query := range layerQueries {
			layerQueriesLookup.Insert(query)
		}
		layerQueriesLookup.Insert(frontend.Variable(1 << 32))
		layerQueriesLookup.Insert(frontend.Variable(1 << 32))
		decommitmentPositions[logSize] = layerQueriesLookup
		queryShape[logSize] = circuitData.DedupedQueriesShape[logSize]

		// the rest of the decommitment positions are the regular queries (no pairs)
		for i := logSize - 1; i >= 0; i-- {
			decommitmentPositions[i] = queries[i]
			queryShape[i] = circuitData.DedupedQueriesShape[i]
		}

		nColumnsPerLogSize := make([]int, 32)
		nColumnsPerLogSize[logSize+1] = 4

		merkleVerifier := NewMerkleVerifier(f.api, f.uapi, f.InnerLayerVerifiers[innerLayerVerifier.layerIndex].proof.Commitment, columnLogSizes, nColumnsPerLogSize)
		if innerLayerVerifier.layerIndex >= len(circuitData.FriInnerLayerBranching) {
			panic("missing FRI inner layer branching data")
		}
		innerBranching := circuitData.FriInnerLayerBranching[innerLayerVerifier.layerIndex]
		merkleVerifier.Verify2(decommitmentPositions, sparseEvaluationsFlattened, f.InnerLayerVerifiers[innerLayerVerifier.layerIndex].proof.Decommitment, queryShape, innerBranching)

		// currentLayerEvals contains g_{i-1}(x_j) folded
		currentLayerEvals = make([]m31.QM31, circuitData.DedupedQueriesShape[logSize])

		// fold g_i evaluations from I_i to I_{i+1} (similar to folding over H_i to I_i but with line domains)
		for i, eval := range sparseEvaluation.evals {
			queryInitial := sparseEvaluation.queryInitials[i]
			domain := innerLayerVerifier.domain.Coset()
			queryInitialLE := uints.U32{queryInitial[3], queryInitial[2], queryInitial[1], queryInitial[0]}
			P := domain.IndexAt(queryInitialLE).Point()
			h0 := eval[0] // g_i(P) = g_i(x_i, y_i)
			h1 := eval[1] // g_i(-P) = g_i(x_i, -y_i)
			evenPart := f.qm31Chip.Add(h0, h1)
			inversePx, _ := f.m31Chip.Inverse(P.X) // x instead of y since we are in the line domain
			oddPart := f.qm31Chip.MulM31(f.qm31Chip.Sub(h0, h1), inversePx)
			folded := f.qm31Chip.Add(evenPart, f.qm31Chip.Mul(innerLayerVerifier.foldingAlpha, oddPart))
			currentLayerEvals[i] = folded
		}

		// update alpha
		previousAlpha = innerLayerVerifier.foldingAlpha
	}

	// Return the final queries and evaluations
	// The final queries are at logSize corresponding to the last processed layer
	finalLogSize := maxLogSize - len(f.InnerLayerVerifiers) + 1
	if finalLogSize < 0 {
		finalLogSize = 0
	}

	return queries[finalLogSize], currentLayerEvals
}

// ╔══════════════════════════════════╗
// ║            Last Layer            ║
// ╚══════════════════════════════════╝

// Verifies the last layer by checking that evaluations match the polynomial evaluated at query points
// This matches the Rust implementation of decommit_last_layer
func (f *FriVerifier) verifyLastLayer2(lastQueries logderivlookup.Table, lastEvaluations []m31.QM31, shape variables.CircuitData) {
	domain := f.lastLayerDomain

	domainLogSize := domain.LogSize()
	_ = domainLogSize
	// For each (query, query_eval) pair
	for i, queryEval := range lastEvaluations {
		query := lastQueries.Lookup(frontend.Variable(i))[0]

		reversedIndex := reverseBitIndex(f.api, f.uapi, query, 2)

		reversedIndexMSB := uints.U32{reversedIndex[3], reversedIndex[2], reversedIndex[1], reversedIndex[0]}
		
		xM31Interface := domain.At(reversedIndexMSB)
		xM31 := xM31Interface.(m31.M31)
		

		xQM31 := m31.NewQM31FromM31(xM31)

		
		expectedEval := f.LastLayerPoly.EvalAt(f.qm31Chip, xQM31)

		f.qm31Chip.AssertEqual(queryEval, expectedEval)
	}
}

// ╔══════════════════════════════════╗
// ║            Utilities             ║
// ╚══════════════════════════════════╝

func (f *FriVerifier) computeDecommitmentPositionsAndRebuildEvals(
	layerQueries logderivlookup.Table,
	evalAtQueries logderivlookup.Table,
	witnessEvals []m31.QM31,
	previousFriWitnessIndex int,
	layerQueriesShape int,
	logSize int,
	shape variables.CircuitData,
) (logderivlookup.Table, []m31.M31, SparseEvaluations, int) {
	layerDecommitmentPositions := logderivlookup.New(f.api)
	pairedEvalsFlattened := make([]m31.M31, 0)
	pairedEvals := make([][2]m31.QM31, 0)
	queryInitials := make([]uints.U32, 0)
	offset := 0
	witnessIndex := previousFriWitnessIndex
	if logSize <= 0 {
		panic("log size must be positive for decommitment branching")
	}
	if logSize-1 >= len(shape.QueriesBranching) {
		panic("queries branching missing layer data")
	}
	branching := shape.QueriesBranching[logSize-1]
	if layerQueriesShape > len(branching) {
		panic("queries branching length mismatch")
	}

	for i := 0; i < layerQueriesShape; i++ {
		base := offset + i

		// get the query initial (query >> 1)
		leftQuery := layerQueries.Lookup(frontend.Variable(base))[0]
		rightQuery := layerQueries.Lookup(frontend.Variable(base + 1))[0]
		_ = rightQuery // keep lookup constraints even though branching is static
		queryU32 := f.uapi.ValueOf(leftQuery)
		queryInitialU32 := f.uapi.Rshift(queryU32, 1)
		queryInitial := f.uapi.ToValue(queryInitialU32)

		// compute and insert the query pair
		leftCandidate := f.api.Mul(queryInitial, frontend.Variable(2))
		rightCandidate := f.api.Add(leftCandidate, frontend.Variable(1))
		layerDecommitmentPositions.Insert(leftCandidate)
		layerDecommitmentPositions.Insert(rightCandidate)

		branchCode := branching[i]
		leftPresent := branchCode&1 == 1
		rightPresent := branchCode&2 == 2

		witness := f.qm31Chip.Zero()
		if !leftPresent || !rightPresent {
			witness = witnessEvals[witnessIndex]
			witnessIndex++
		}

		eval0Native := evalAtQueries.Lookup(base)[0]
		eval0 := f.qm31Chip.DecodeNative(eval0Native)
		eval1Native := evalAtQueries.Lookup(frontend.Variable(base + 1))[0]
		eval1 := f.qm31Chip.DecodeNative(eval1Native)

		var leftEval m31.QM31
		var rightEval m31.QM31
		if leftPresent {
			leftEval = eval0
			if rightPresent {
				rightEval = eval1
			} else {
				rightEval = witness
			}
		} else {
			leftEval = witness
			rightEval = eval0
		}

		// update the offset
		if leftPresent && rightPresent {
			offset++
		}

		// flatten the evaluations into 4 M31 elements for use in the merkle decommitment verifier
		leftEvalComponents := leftEval.Components()
		pairedEvalsFlattened = append(pairedEvalsFlattened, leftEvalComponents[0], leftEvalComponents[1], leftEvalComponents[2], leftEvalComponents[3])
		rightEvalComponents := rightEval.Components()
		pairedEvalsFlattened = append(pairedEvalsFlattened, rightEvalComponents[0], rightEvalComponents[1], rightEvalComponents[2], rightEvalComponents[3])

		// append the paired evaluations to the list
		pairedEvals = append(pairedEvals, [2]m31.QM31{leftEval, rightEval})

		// build the sparse evaluations for the inner layer verifier
		queryInitials = append(queryInitials, reverseBitIndex(f.api, f.uapi, leftCandidate, logSize))
	}

	sparseEvaluation := SparseEvaluations{
		queryInitials: queryInitials,
		evals:         pairedEvals,
	}

	return layerDecommitmentPositions, pairedEvalsFlattened, sparseEvaluation, witnessIndex
}
