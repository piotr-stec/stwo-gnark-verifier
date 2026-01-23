package verifier

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/blake2s"
	"github.com/HerodotusDev/stwo-gnark-verifier/channel"
	"github.com/HerodotusDev/stwo-gnark-verifier/circle"
	"github.com/HerodotusDev/stwo-gnark-verifier/components"
	"github.com/HerodotusDev/stwo-gnark-verifier/fri"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/HerodotusDev/stwo-gnark-verifier/utils"
	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// VerifierChip is a circuit gadget for verifying a Stwo proof
type VerifierChip struct {
	api     frontend.API `gnark:"-"`
	uapi    *uints.BinaryField[uints.U32]
	bapi    *uints.Bytes
	blake2s *blake2s.Blake2sChip
	channel *channel.Channel
	m31     *m31.M31Chip
	qm31    *m31.QM31Chip
	circle  *circle.CircleChip
}

// NewVerifierChip initializes a new VerifierChip
func NewVerifierChip(api frontend.API) *VerifierChip {
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		panic(err)
	}
	bapi, err := uints.NewBytes(api)
	if err != nil {
		panic(err)
	}
	blake2sChip := blake2s.NewBlake2sChip(api)
	m31Chip := m31.NewM31Chip(api)
	qm31Chip := m31.NewQM31Chip(m31Chip)
	circleChip := circle.NewCircleChip(api, m31Chip, qm31Chip)
	channelChip := channel.NewChannel(api)
	return &VerifierChip{
		api:     api,
		uapi:    uapi,
		bapi:    bapi,
		blake2s: blake2sChip,
		channel: channelChip,
		m31:     m31Chip,
		qm31:    qm31Chip,
		circle:  circleChip,
	}
}

// Verify verifies a Stwo proof with generic AIR support
// This is the main entry point for verifying proofs, analogous to Solidity's verify function
//   - proof is the STARK proof to verify (includes composition polynomial)
//   - params contains verification parameters (components, tree info, digest, etc.)
func (c *VerifierChip) Verify(proof variables.StarkProof, params variables.VerificationParams) {
	// Initialize channel with digest and nDraws (like Solidity's initializeWith)
	c.channel.InitializeWith(params.Digest, params.NDraws)

	// Initialize commitment scheme verifier with tree information
	// This already mixes all commitments (including composition poly) into the channel
	commitmentVerifier := c.initializeCommitmentScheme(proof, params)

	// Draw random coefficient for OODS from channel
	randomCoeff := c.channel.DrawFelt()

	// Composition polynomial is the last tree
	numTrees := len(proof.Commitments)
	cpTreeIdx := numTrees - 1

	// ╔══════════════════════════════════╗
	// ║               OODS               ║
	// ╚══════════════════════════════════╝

	// Verify OODS: get random point and evaluate constraints
	oodsPoint := c.circle.GetRandomPoint(c.channel)

	// Extract CP evaluation from sampled values (last tree in sampled values)
	compositionOodsEval := c.qm31.FromPartialEvals(
		proof.SampledValues[cpTreeIdx][0][0],
		proof.SampledValues[cpTreeIdx][1][0],
		proof.SampledValues[cpTreeIdx][2][0],
		proof.SampledValues[cpTreeIdx][3][0],
	)

	// Evaluate composition polynomial at OODS point
	// The composition polynomial is now part of the proof, making this generic
	constraintsOodsEval := proof.CompositionPoly.EvalAt(c.qm31, oodsPoint)

	// Verify OODS consistency
	c.qm31.AssertEqual(compositionOodsEval, constraintsOodsEval)

	// ╔══════════════════════════════════╗
	// ║          FRI Commitment          ║
	// ╚══════════════════════════════════╝

	// Mix flatten sampled values into channel
	flattenedSampledValues := utils.FlattenTree(utils.FlattenTree(proof.SampledValues))
	c.channel.MixFelts(flattenedSampledValues)

	// Draw random coeff for FRI
	randomCoeff = c.channel.DrawFelt()

	// Compute bounds (column log sizes deduped, in decreasing order and not blew up)
	bounds := commitmentVerifier.Bounds()


	// Verification of commitment stage of FRI
	friVerifier := fri.NewFriVerifier(c.api, c.uapi, c.channel, c.qm31, c.circle, commitmentVerifier.PcsConfig.FriConfig, proof.FriProof, bounds, circuitData)

	// Proof of work
	c.channel.MixAndCheckPowNonce(proof.ProofOfWork, int(commitmentVerifier.PcsConfig.PowBits))

	// ╔══════════════════════════════════╗
	// ║              Queries             ║
	// ╚══════════════════════════════════╝

	// Generate base layer queries and verify they match the hinted queries
	maxLogSize := bounds[0]
	baseLayerQueries := c.channel.GenerateBaseLayerQueries(maxLogSize, commitmentVerifier.PcsConfig.FriConfig.NQueries)
	queries := utils.GenerateQueries(c.api, baseLayerQueries, commitmentVerifier.PcsConfig.FriConfig.NQueries, circuitData.DedupedQueriesShape, circuitData.MaxLogSize)
	queriesLookup := utils.ToLookupTable(c.api, queries)

	// ╔══════════════════════════════════╗
	// ║        Trace decommitments       ║
	// ╚══════════════════════════════════╝

	// Verify merkle decommitments
	for treeIndex, tree := range commitmentVerifier.Trees {
		tree.Verify(queriesLookup, proof.QueriedValues[treeIndex], proof.Decommitments[treeIndex])
	}

	// ╔══════════════════════════════════╗
	// ║               FRI                ║
	// ╚══════════════════════════════════╝

	// Compute mask points from generic params (analogous to Solidity's maskPoints)
	maskPoints := components.ComputeGenericMaskPoints(c.api, c.uapi, c.circle, oodsPoint, params)

	// Verify FRI quotients
	friAnswers := friVerifier.FriQuotientEvaluations(proof.SampledValues, maskPoints, queries, proof.QueriedValues, randomCoeff)
	friAnswersEncoded := fri.EncodeFriAnswers(c.qm31, friAnswers)
	friAnswersLookup := utils.ToLookupTable(c.api, friAnswersEncoded)
	friVerifier.Verify(queriesLookup, friAnswersLookup)
}

// initializeCommitmentScheme initializes the commitment scheme verifier with tree information
func (c *VerifierChip) initializeCommitmentScheme(proof variables.StarkProof, params variables.VerificationParams) *fri.CommitmentSchemeVerifier {
	// Tree roots are already in correct format ([32]uints.U8)
	// Create commitment scheme verifier using generic constructor
	return fri.NewCommitmentSchemeVerifierGeneric(
		c.api,
		c.uapi,
		c.channel,
		proof.Config,
		params.TreeRoots,
		params.TreeColumnLogSizes,
	)
}

// // VerifyLegacy is the old Cairo-specific verification function
// // Kept for backward compatibility with existing tests
// // DEPRECATED: Use Verify with VerificationParams instead
// func (c *VerifierChip) VerifyLegacy(proof variables.StarkProof, pcsConfig variables.PcsConfig, circuitData variables.CircuitData, commitmentVerifier fri.CommitmentSchemeVerifier, compositionLogDegreeBound frontend.Variable, compositionPolynomial circle.SecureCirclePoly) {

// 	// Draw random coeff from channel for OODS
// 	randomCoeff := c.channel.DrawFelt()

// 	// Verify composition polynomial commitment
// 	compositionLogSizes := []frontend.Variable{compositionLogDegreeBound, compositionLogDegreeBound, compositionLogDegreeBound, compositionLogDegreeBound}
// 	commitmentVerifier.Commit(cairo_components.CP_IDX, proof.Commitments[cairo_components.CP_IDX], compositionLogSizes, c.channel)

// 	// ╔══════════════════════════════════╗
// 	// ║               OODS               ║
// 	// ╚══════════════════════════════════╝

// 	// Verify OODS
// 	oodsPoint := c.circle.GetRandomPoint(c.channel)
// 	components := components.NewComponents(c.api, c.m31, c.qm31, c.circle, cairoInteractionElements, proof.Claim, proof.InteractionClaim, oodsPoint, circuitData)

// 	// Extract CP evaluation from sampled values
// 	compositionOodsEval := c.qm31.FromPartialEvals(
// 		proof.SampledValues[cairo_components.CP_IDX][0][0],
// 		proof.SampledValues[cairo_components.CP_IDX][1][0],
// 		proof.SampledValues[cairo_components.CP_IDX][2][0],
// 		proof.SampledValues[cairo_components.CP_IDX][3][0],
// 	)

// 	// evaluate constraints using sampled values
// 	constraintsOodsEval := compositionPolynomial.EvalAt(c.qm31, oodsPoint)

// 	// verify OODS
// 	c.qm31.AssertEqual(compositionOodsEval, constraintsOodsEval)

// 	// ╔══════════════════════════════════╗
// 	// ║          FRI Commitment          ║
// 	// ╚══════════════════════════════════╝

// 	// Mix flatten sampled values into channel
// 	flattenedSampledValues := utils.FlattenTree(utils.FlattenTree(proof.StarkProof.SampledValues))
// 	c.channel.MixFelts(flattenedSampledValues)

// 	// Draw random coeff for FRI
// 	randomCoeff = c.channel.DrawFelt()

// 	// Compute bounds (column log sizes deduped, in decreasing order and not blew up)
// 	bounds := commitmentVerifier.Bounds()

// 	// Verification of commitment stage of FRI
// 	friVerifier := fri.NewFriVerifier(c.api, c.uapi, c.channel, c.qm31, c.circle, commitmentVerifier.PcsConfig.FriConfig, proof.StarkProof.FriProof, bounds, circuitData)

// 	// Proof of work
// 	c.channel.MixAndCheckPowNonce(proof.StarkProof.ProofOfWork, int(commitmentVerifier.PcsConfig.PowBits))

// 	// ╔══════════════════════════════════╗
// 	// ║              Queries             ║
// 	// ╚══════════════════════════════════╝

// 	// Generate base layer queries and verify they match the hinted queries
// 	maxLogSize := bounds[0]
// 	baseLayerQueries := c.channel.GenerateBaseLayerQueries(maxLogSize, commitmentVerifier.PcsConfig.FriConfig.NQueries)
// 	queries := utils.GenerateQueries(c.api, baseLayerQueries, commitmentVerifier.PcsConfig.FriConfig.NQueries, circuitData.DedupedQueriesShape, circuitData.MaxLogSize)
// 	queriesLookup := utils.ToLookupTable(c.api, queries)

// 	// ╔══════════════════════════════════╗
// 	// ║        Trace decommitments       ║
// 	// ╚══════════════════════════════════╝

// 	// Verify merkle decommitments
// 	for treeIndex, tree := range commitmentVerifier.Trees {
// 		tree.Verify(queriesLookup, proof.QueriedValues[treeIndex], proof.Decommitments[treeIndex], circuitData.DedupedQueriesShape, circuitData.QueriesBranching)
// 	}

// 	// ╔══════════════════════════════════╗
// 	// ║               FRI                ║
// 	// ╚══════════════════════════════════╝

// 	// Compute mask points
// 	maskPoints := components.MaskPoints(c.api, proof.Claim, oodsPoint, c.circle, circuitData)

// 	// Verify FRI quotients
// 	friAnswers := friVerifier.FriQuotientEvaluations(proof.SampledValues, maskPoints, queries, proof.QueriedValues, randomCoeff)
// 	friAnswersEncoded := fri.EncodeFriAnswers(c.qm31, friAnswers)
// 	friAnswersLookup := utils.ToLookupTable(c.api, friAnswersEncoded)
// 	friVerifier.Verify(queriesLookup, friAnswersLookup)
// }
