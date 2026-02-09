package verifier

import (
	"encoding/hex"
	"fmt"
	"math/big"

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
func (c *VerifierChip) Verify(proof variables.StarkProof, params variables.VerificationParams, shape variables.CircuitData) {
	// DEBUG: Check if TreeRoots are available
	// fmt.Printf("DEBUG Verify: len(params.TreeRoots) = %d\n", len(params.TreeRoots))
	// if len(params.TreeRoots) > 0 {
	// 	fmt.Printf("DEBUG Verify: params.TreeRoots[0][0] = %v\n", params.TreeRoots[0][0])
	// }
	// fmt.Printf("DEBUG Verify: params.Digest[0] = %v\n", params.Digest[0])

	// // Initialize channel with digest and nDraws (like Solidity's initializeWith)
	c.channel.InitializeWith(params.Digest, params.NDraws)

	// c.channel.DebugPrint("After initialization")

	// Initialize commitment scheme verifier with tree information
	// This already mixes all commitments (including composition poly) into the channel
	commitmentVerifier := c.initializeCommitmentScheme(proof, params)

	// Draw random coefficient for OODS from channel
	randomCoeff := c.channel.DrawFelt()
	_ = randomCoeff

	// Composition polynomial is the last tree
	numTrees := len(proof.Commitments)
	cpTreeIdx := numTrees - 1

	// Commit to Composition Polynomial
	// In Solidity: _performCompositionCommit
	// compositionLogDegreeBound is the degree bound, we need commitment domain log size
	compositionLogDegreeBound := params.ComponentsCompositionLogDegreeBound
	logBlowupFactor := commitmentVerifier.PcsConfig.FriConfig.LogBlowupFactor
	compositionCommitmentLogSize := compositionLogDegreeBound + logBlowupFactor
	fmt.Printf("DEBUG Verify: compositionLogDegreeBound = %v, commitmentLogSize = %v\n", compositionLogDegreeBound, compositionCommitmentLogSize)
	compositionSizes := []int{compositionCommitmentLogSize, compositionCommitmentLogSize, compositionCommitmentLogSize, compositionCommitmentLogSize}
	fmt.Printf("Debug commitment verifier log sizes: %v\n", commitmentVerifier.TreeColumnLogSizes)
	commitmentVerifier.Commit(
		cpTreeIdx,
		proof.Commitments[cpTreeIdx],
		compositionSizes,
		c.channel,
	)
	
	fmt.Printf("Debug commitment verifier log sizes: %v\n", commitmentVerifier.TreeColumnLogSizes)

	// // Debug print compostion sizes
	// fmt.Printf("DEBUG Verify: compositionSizes = %v\n", proof.Commitments[cpTreeIdx])
	// // DEBUG: Print channel state after composition commit
	// c.channel.DebugPrint("After composition commit")

	// ╔══════════════════════════════════╗
	// ║               OODS               ║
	// ╚══════════════════════════════════╝

	// Verify OODS: get random point and evaluate constraints
	oodsPoint := c.circle.GetRandomPoint(c.channel)

	// DEBUG: Print OODS point
	fmt.Printf("DEBUG Verify: oodsPoint = %v\n", oodsPoint)

	// Extract CP evaluation from sampled values (last tree in sampled values)
	// SampledValues is [tree][column][point]
	// For CP (last tree), we expect 4 columns (secure extension degree) and 1 point (oods)
	// SampledValues[cpTreeIdx][0][0] corresponds to column 0 at oods point
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
	c.channel.DebugPrint("After flattened sampled values")

	// Draw random coeff for FRI
	friRandomCoeff := c.channel.DrawFelt()
	fmt.Printf("Random coeff = %v", friRandomCoeff)

	// fmt.Printf("Debug commiyment verifier log sizes: %v\n", commitmentVerifier.TreeColumnLogSizes)

	// // Compute bounds (column log sizes deduped, in decreasing order and not blew up)
	bounds := commitmentVerifier.Bounds2(shape)
	fmt.Printf("bounds = %v\n", bounds)
	c.channel.DebugPrint("Before New Fri verifier")

	// Verification of commitment stage of FRI
	friVerifier := fri.NewFriVerifier(c.api, c.uapi, c.channel, c.qm31, c.circle, commitmentVerifier.PcsConfig.FriConfig, proof.FriProof, bounds, shape)
	c.channel.DebugPrint("After New Fri verifier")
	fmt.Printf("DEBUG Verify: Before CheckPowNonce\n")

	// Proof of work
	c.channel.MixAndCheckPowNonce(proof.ProofOfWork, int(commitmentVerifier.PcsConfig.PowBits))
	c.channel.DebugPrint("After mix and check proof of work")
	// Proof of work
	// c.channel.CheckPowNonce(proof.ProofOfWork, int(commitmentVerifier.PcsConfig.PowBits))
	// c.channel.MixU64(proof.ProofOfWork)
	// c.channel.DebugPrint("After mix proof of work")

	// ╔══════════════════════════════════╗
	// ║              Queries             ║
	// ╚══════════════════════════════════╝
	maxLogSize := bounds[0]

	baseLayerQueries := c.channel.GenerateBaseLayerQueries2(maxLogSize, commitmentVerifier.PcsConfig.FriConfig.NQueries)
	fmt.Printf("baseLayerQueries generate = %v\n", baseLayerQueries)

	// fmt.Printf("After base layerqueries generate")
	fmt.Printf("Max log size shape: %v", shape.MaxLogSize)

	// Generate all queries for all layers
	queries2 := utils.GenerateQueries2(c.api, baseLayerQueries, commitmentVerifier.PcsConfig.FriConfig.NQueries, shape.DedupedQueriesShape, shape.MaxLogSize)

	queriesLookup := utils.ToLookupTable(c.api, queries2)
		fmt.Printf("Genereted queries: %v\n", queries2)

	// ╔══════════════════════════════════╗
	// ║        Trace decommitments       ║
	// ╚══════════════════════════════════╝

	// Verify merkle decommitments
	for treeIndex, tree := range commitmentVerifier.Trees {
		if tree == nil {
			continue
		}
		fmt.Printf("Tree column log sizes: %v\n", tree.ColumnLogSizes)
		// We need to pass valid query positions for this tree's log sizes
		// if( len(tree.ColumnLogSizes) != len(shape.DedupedQueriesShape) ){ 
		// 	panic("Mismatch in column log sizes and deduped query shape lengths")
		// }
		tree.Verify2(queriesLookup, proof.QueriedValues[treeIndex], proof.Decommitments[treeIndex], shape.DedupedQueriesShape, shape.QueriesBranching)
	}
	// fmt.Printf("After tree verify\n")
	// // ╔══════════════════════════════════╗
	// // ║               FRI                ║
	// // ╚══════════════════════════════════╝
	maskPoints := components.ComputeGenericMaskPoints(c.api, c.uapi, c.circle, oodsPoint, params)
	// fmt.Printf("DEBUG Verify: maskPoints before composition = %v\n", maskPoints)

	const SECURE_EXTENSION_DEGREE = 4
	compositionMaskPoints := make([][]circle.Point, SECURE_EXTENSION_DEGREE)
	for i := 0; i < SECURE_EXTENSION_DEGREE; i++ {
		compositionMaskPoints[i] = []circle.Point{oodsPoint}
	}
	maskPoints = append(maskPoints, compositionMaskPoints)
	fmt.Printf("DEBUG Verify: maskPoints after composition = %v\n", maskPoints)

	// fmt.Printf("Queries = %v\n", queries)
	// fmt.Printf("Sampled values proof = %v\n", proof.SampledValues)
	// // Verify FRI quotients
	friAnswers := friVerifier.FriQuotientEvaluations2(proof.SampledValues, maskPoints, queries2, proof.QueriedValues, friRandomCoeff, shape)
	fmt.Printf("After FRI Quotient Evaluations\n")
	fmt.Printf("Fri answers = %v\n", friAnswers)

	friAnswersEncoded := fri.EncodeFriAnswers(c.qm31, friAnswers)

	friAnswersLookup := utils.ToLookupTable(c.api, friAnswersEncoded)
	fmt.Printf("After to Lookup table=%v\n",friAnswersLookup)

	friVerifier.Verify2(queriesLookup, friAnswersLookup, shape)
}

// initializeCommitmentScheme initializes the commitment scheme verifier with tree information
func (c *VerifierChip) initializeCommitmentScheme(proof variables.StarkProof, params variables.VerificationParams) *fri.CommitmentSchemeVerifier {
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

// debugPrintDigest prints a digest in hex format for debugging
func (c *VerifierChip) debugPrintDigest(label string, digest [8]uints.U32) {
	fmt.Printf("\n=== %s ===\n", label)

	// Convert to bytes in little-endian word order
	bytes := make([]byte, 32)
	for i := 0; i < 8; i++ {
		word := digest[i]
		for j := 0; j < 4; j++ {
			val := word[j].Val
			var byteVal byte
			switch v := val.(type) {
			case int:
				byteVal = byte(v)
			case *big.Int:
				byteVal = byte(v.Uint64())
			case uint64:
				byteVal = byte(v)
			default:
				byteVal = 0
			}
			bytes[i*4+j] = byteVal
		}
	}
	fmt.Printf("Hex: 0x%s\n", hex.EncodeToString(bytes))

	// Also print in big-endian
	bytesReversed := make([]byte, 32)
	for i := 0; i < 8; i++ {
		word := digest[7-i]
		for j := 0; j < 4; j++ {
			val := word[3-j].Val
			var byteVal byte
			switch v := val.(type) {
			case int:
				byteVal = byte(v)
			case *big.Int:
				byteVal = byte(v.Uint64())
			case uint64:
				byteVal = byte(v)
			default:
				byteVal = 0
			}
			bytesReversed[i*4+j] = byteVal
		}
	}
	fmt.Printf("Hex (big-endian): 0x%s\n", hex.EncodeToString(bytesReversed))
	fmt.Println("===================")
}
