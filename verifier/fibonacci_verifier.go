// NOTE: This file is temporarily disabled due to incompatibility with the new generic verifier API.
// It needs to be updated to use the new VerificationParams structure instead of circuitData.
// See REFACTORING_NOTES.md for details on the migration path.

package verifier

// TODO: Uncomment and update this code to use the new generic API
// See docs/GENERIC_VERIFICATION_GUIDE.md for migration examples

// import (
// 	"github.com/HerodotusDev/stwo-gnark-verifier/circle"
// 	"github.com/HerodotusDev/stwo-gnark-verifier/components/fibonacci_components"
// 	"github.com/HerodotusDev/stwo-gnark-verifier/fri"
// 	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
// 	"github.com/HerodotusDev/stwo-gnark-verifier/utils"
// 	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
// 	"github.com/consensys/gnark/frontend"
// )


// // VerifyFibonacci verifies a Fibonacci Stwo proof
// //   - proof is the Fibonacci proof to verify
// //   - pcsConfig is the PCS configuration (default or production)
// //   - circuitData are the circuit shapes (obtained from a rust verifier run)
// //   - compositionLogDegreeBound is the log degree bound of the composition polynomial
// func (c *VerifierChip) VerifyFibonacci(
// 	proof variables.StarkProof,
// 	pcsConfig variables.PcsConfig,
// 	commitmentVerifier fri.CommitmentSchemeVerifier,
// 	compositionLogDegreeBound frontend.Variable,
// ) {
// 	// Draw random coeff from channel for OODS
// 	randomCoeff := c.channel.DrawFelt()

// 	// Verify composition polynomial commitment
// 	compositionLogSizes := []frontend.Variable{
// 		compositionLogDegreeBound,
// 		compositionLogDegreeBound,
// 		compositionLogDegreeBound,
// 		compositionLogDegreeBound,
// 	}
// 	commitmentVerifier.Commit(
// 		fibonacci_components.CP_IDX,
// 		proof.Commitments[fibonacci_components.CP_IDX],
// 		compositionLogSizes,
// 		c.channel,
// 	)

// 	// ╔══════════════════════════════════╗
// 	// ║               OODS               ║
// 	// ╚══════════════════════════════════╝

// 	// Verify OODS
// 	oodsPoint := c.circle.GetRandomPoint(c.channel)

// 	// Create Fibonacci component
// 	fibComponent := fibonacci_components.NewFibonacciComponent(
// 		c.api,
// 		c.m31,
// 		c.qm31,
// 		m31.NewQM31Unchecked(1, 0, 0, 0), // vanishEvalInv - simplified for now
// 		fibonacci_components.FibonacciClaim{
// 			LogSize: circuitData.LogSize,
// 		},
// 	)

// 	// Extract CP evaluation from sampled values
// 	compositionOodsEval := c.qm31.FromPartialEvals(
// 		proof.SampledValues[fibonacci_components.CP_IDX][0][0],
// 		proof.SampledValues[fibonacci_components.CP_IDX][1][0],
// 		proof.SampledValues[fibonacci_components.CP_IDX][2][0],
// 		proof.SampledValues[fibonacci_components.CP_IDX][3][0],
// 	)

// 	// Create traces from sampled values
// 	traces := fibonacci_components.NewTraces(
// 		proof.SampledValues[fibonacci_components.TRACE_IDX],
// 	)

// 	// Evaluate constraints using sampled values
// 	constraintsOodsEval := fibComponent.Evaluate(traces, randomCoeff)

// 	// Verify OODS
// 	c.qm31.AssertEqual(compositionOodsEval, constraintsOodsEval)

// 	// ╔══════════════════════════════════╗
// 	// ║          FRI Commitment          ║
// 	// ╚══════════════════════════════════╝

// 	// Mix flatten sampled values into channel
// 	flattenedSampledValues := utils.FlattenTree(utils.FlattenTree(proof.SampledValues))
// 	c.channel.MixFelts(flattenedSampledValues)

// 	// Draw random coeff for FRI
// 	randomCoeff = c.channel.DrawFelt()

// 	// Compute bounds (column log sizes deduped, in decreasing order and not blew up)
// 	bounds := commitmentVerifier.Bounds()

// 	// Verification of commitment stage of FRI
// 	friVerifier := fri.NewFriVerifier(
// 		c.api,
// 		c.uapi,
// 		c.channel,
// 		c.qm31,
// 		c.circle,
// 		commitmentVerifier.PcsConfig.FriConfig,
// 		proof.FriProof,
// 		bounds,
// 		circuitData.ToCircuitData(),
// 	)

// 	// Proof of work
// 	c.channel.MixAndCheckPowNonce(
// 		proof.ProofOfWork,
// 		int(commitmentVerifier.PcsConfig.PowBits),
// 	)

// 	// ╔══════════════════════════════════╗
// 	// ║              Queries             ║
// 	// ╚══════════════════════════════════╝

// 	// Generate base layer queries and verify they match the hinted queries
// 	maxLogSize := bounds[0]
// 	baseLayerQueries := c.channel.GenerateBaseLayerQueries(
// 		maxLogSize,
// 		commitmentVerifier.PcsConfig.FriConfig.NQueries,
// 	)
// 	queries := utils.GenerateQueries(
// 		c.api,
// 		baseLayerQueries,
// 		commitmentVerifier.PcsConfig.FriConfig.NQueries,
// 		circuitData.DedupedQueriesShape,
// 		circuitData.MaxLogSize,
// 	)
// 	queriesLookup := utils.ToLookupTable(c.api, queries)

// 	// ╔══════════════════════════════════╗
// 	// ║        Trace decommitments       ║
// 	// ╚══════════════════════════════════╝

// 	// Verify merkle decommitments
// 	for treeIndex, tree := range commitmentVerifier.Trees {
// 		tree.Verify(
// 			queriesLookup,
// 			proof.QueriedValues[treeIndex],
// 			proof.Decommitments[treeIndex],
// 			circuitData.DedupedQueriesShape,
// 			circuitData.QueriesBranching,
// 		)
// 	}

// 	// ╔══════════════════════════════════╗
// 	// ║               FRI                ║
// 	// ╚══════════════════════════════════╝

// 	// Compute mask points for Fibonacci
// 	maskPoints := computeFibonacciMaskPoints(c.api, c.circle, oodsPoint, circuitData)

// 	// Verify FRI quotients
// 	friAnswers := friVerifier.FriQuotientEvaluations(
// 		proof.SampledValues,
// 		maskPoints,
// 		queries,
// 		proof.QueriedValues,
// 		randomCoeff,
// 	)
// 	friAnswersEncoded := fri.EncodeFriAnswers(c.qm31, friAnswers)
// 	friAnswersLookup := utils.ToLookupTable(c.api, friAnswersEncoded)
// 	friVerifier.Verify(queriesLookup, friAnswersLookup)
// }

// // computeFibonacciMaskPoints computes the mask points for Fibonacci
// // For Fibonacci we need 3 consecutive points: OODS-2, OODS-1, OODS
// func computeFibonacciMaskPoints(
// 	api frontend.API,
// 	circleChip *circle.CircleChip,
// 	oodsPoint circle.Point,
// 	circuitData variables.FibonacciCircuitData,
// ) [][]circle.Point {
// 	// For Fibonacci, we have one trace column with 3 mask points
// 	// The mask points are at offsets -2, -1, 0 from the OODS point

// 	oods := oodsPoint
// 	oodsMinus1 := circleChip.AddStep(oodsPoint, m31.NewM31Unchecked(api.Neg(1)))
// 	oodsMinus2 := circleChip.AddStep(oodsMinus1, m31.NewM31Unchecked(api.Neg(1)))

// 	// Return mask points: [tree_idx][column_idx][]Point
// 	// For Fibonacci: 3 trees (preprocessed empty, trace, CP)
// 	maskPoints := make([][]circle.Point, fibonacci_components.N_TREES)

// 	// Tree 0: Preprocessed (empty)
// 	maskPoints[fibonacci_components.PREPROCESSED_IDX] = []circle.Point{}

// 	// Tree 1: Trace - one column with 3 mask points
// 	maskPoints[fibonacci_components.TRACE_IDX] = []circle.Point{
// 		oodsMinus2, oodsMinus1, oods,
// 	}

// 	// Tree 2: Composition polynomial - standard 4 evaluation points
// 	maskPoints[fibonacci_components.CP_IDX] = []circle.Point{
// 		oods, oods, oods, oods,
// 	}

// 	return maskPoints
// }