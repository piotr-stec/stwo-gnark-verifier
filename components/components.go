package components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/circle"
	"github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/consensys/gnark/frontend"
)

// Components is a chip for OODS
type Components struct {
	api    frontend.API
	m31    *m31.M31Chip
	qm31   *m31.QM31Chip
	circle *circle.CircleChip

	addApOpcodes                cairo_components.AddApOpcodeComponent
	addModBuiltin               cairo_components.AddModBuiltinComponent
	addOpcodes                  cairo_components.AddOpcodeComponent
	addSmallOpcodes             cairo_components.AddSmallOpcodeComponent
	assertEqDoubleDerefOpcodes  cairo_components.AssertEqDoubleDerefOpcodeComponent
	assertEqImmOpcodes          cairo_components.AssertEqImmOpcodeComponent
	assertEqOpcodes             cairo_components.AssertEqOpcodeComponent
	bitwiseBuiltin              cairo_components.BitwiseBuiltinComponent
	blakeCompressOpcodes        cairo_components.BlakeCompressOpcodeComponent
	blakeG                      cairo_components.BlakeGComponent
	blakeRound                  cairo_components.BlakeRoundComponent
	blakeRoundSigma             cairo_components.BlakeRoundSigmaComponent
	callOpcodes                 cairo_components.CallOpcodeComponent
	callRelImmOpcodes           cairo_components.CallRelImmOpcodeComponent
	cube252                     cairo_components.Cube252Component
	genericOpcodes              cairo_components.GenericOpcodeComponent
	jnzOpcodes                  cairo_components.JnzOpcodeComponent
	jnzTakenOpcodes             cairo_components.JnzTakenOpcodeComponent
	jumpDoubleDerefOpcodes      cairo_components.JumpDoubleDerefOpcodeComponent
	jumpOpcodes                 cairo_components.JumpOpcodeComponent
	jumpRelImmOpcodes           cairo_components.JumpRelImmOpcodeComponent
	jumpRelOpcodes              cairo_components.JumpRelOpcodeComponent
	memoryAddressToID           cairo_components.MemoryAddressToIDComponent
	memoryIDToBigBigComponents  cairo_components.MemoryIDToBigBigComponent
	memoryIDToBigSmallComponent cairo_components.MemoryIDToBigSmallComponent
	mulModBuiltin               cairo_components.MulModBuiltinComponent
	mulOpcodes                  cairo_components.MulOpcodeComponent
	mulSmallOpcodes             cairo_components.MulSmallOpcodeComponent
	partialEcMul                cairo_components.PartialEcMulComponent
	pedersenBuiltin             cairo_components.PedersenBuiltinComponent
	pedersenPointsTable         cairo_components.PedersenPointsTableComponent
	poseidon3PartialRoundsChain cairo_components.Poseidon3PartialRoundsChainComponent
	poseidonBuiltin             cairo_components.PoseidonBuiltinComponent
	poseidonFullRoundChain      cairo_components.PoseidonFullRoundChainComponent
	poseidonRoundKeys           cairo_components.PoseidonRoundKeysComponent
	qm31Opcodes                 cairo_components.Qm31OpcodeComponent
	rangeCheck11                cairo_components.RangeCheck11Component
	rangeCheck12                cairo_components.RangeCheck12Component
	rangeCheck18                cairo_components.RangeCheck18Component
	rangeCheck19                cairo_components.RangeCheck19Component
	rangeCheck33333             cairo_components.RangeCheck33333Component
	rangeCheck3663              cairo_components.RangeCheck3663Component
	rangeCheck43                cairo_components.RangeCheck43Component
	rangeCheck4444              cairo_components.RangeCheck4444Component
	rangeCheck44                cairo_components.RangeCheck44Component
	rangeCheck54                cairo_components.RangeCheck54Component
	rangeCheck6                 cairo_components.RangeCheck6Component
	rangeCheck725               cairo_components.RangeCheck725Component
	rangeCheck8                 cairo_components.RangeCheck8Component
	rangeCheck99                cairo_components.RangeCheck99Component
	rangeCheckBuiltin128        cairo_components.RangeCheck128BuiltinComponent
	rangeCheckBuiltin96         cairo_components.RangeCheck96BuiltinComponent
	rangeCheckFelt252Width27    cairo_components.RangeCheckFelt252Width27Component
	retOpcodes                  cairo_components.RetOpcodeComponent
	tripleXor32                 cairo_components.TripleXor32Component
	verifyBitwiseXor12          cairo_components.VerifyBitwiseXor12Component
	verifyBitwiseXor4           cairo_components.VerifyBitwiseXor4Component
	verifyBitwiseXor7           cairo_components.VerifyBitwiseXor7Component
	verifyBitwiseXor8           cairo_components.VerifyBitwiseXor8Component
	verifyBitwiseXor9           cairo_components.VerifyBitwiseXor9Component
	verifyInstruction           cairo_components.VerifyInstructionComponent
}

// NewComponents creates a new OODS chip
func NewComponents(
	api frontend.API,
	m31Chip *m31.M31Chip,
	qm31Chip *m31.QM31Chip,
	circleChip *circle.CircleChip,
	cairoInteractionElements variables.CairoInteractionElements,
	claim variables.CairoClaim,
	interactionClaim variables.CairoInteractionClaim,
	oodsPoint circle.Point,
) *Components {
	comp := &Components{
		api:    api,
		m31:    m31Chip,
		qm31:   qm31Chip,
		circle: circleChip,
	}

	// opcode components

	return comp
}

// Evaluate evaluates the components at the sampled values
// Each component has an Evaluate method that pops the front of the sampled values and evaluates the constraints adding the result to the running sum
// This is highly order dependent, so the components need to be correctly ordered
func (c Components) Evaluate(sampledValues [][][]m31.QM31, randomCoeff m31.QM31, circuitData variables.CircuitData) m31.QM31 {
	// Prepare sampled values
	preprocessedSampledValuesRaw := sampledValues[cairo_components.PREPROCESSED_IDX]
	preprocessedSampledValues := cairo_components.NewPreprocessedSampledValues(c.api, c.qm31, preprocessedSampledValuesRaw)
	traceSampledValues := sampledValues[cairo_components.MAIN_IDX]
	interactionSampledValues := sampledValues[cairo_components.INTERACTION_IDX]

	traces := cairo_components.NewTraces(preprocessedSampledValues, traceSampledValues, interactionSampledValues)

	// Evaluate components
	sum := c.qm31.Zero()

	// Opcode components
	if circuitData.ComponentConfig[0] {
		sum = c.addOpcodes.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[1] {
		sum = c.addSmallOpcodes.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[2] {
		sum = c.addApOpcodes.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[3] {
		sum = c.assertEqOpcodes.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[4] {
		sum = c.assertEqImmOpcodes.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[5] {
		sum = c.assertEqDoubleDerefOpcodes.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[6] {
		sum = c.blakeCompressOpcodes.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[7] {
		sum = c.callOpcodes.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[8] {
		sum = c.callRelImmOpcodes.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[9] {
		sum = c.genericOpcodes.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[10] {
		sum = c.jnzOpcodes.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[11] {
		sum = c.jnzTakenOpcodes.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[12] {
		sum = c.jumpOpcodes.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[13] {
		sum = c.jumpDoubleDerefOpcodes.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[14] {
		sum = c.jumpRelOpcodes.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[15] {
		sum = c.jumpRelImmOpcodes.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[16] {
		sum = c.mulOpcodes.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[17] {
		sum = c.mulSmallOpcodes.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[18] {
		sum = c.qm31Opcodes.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[19] {
		sum = c.retOpcodes.Evaluate(sum, traces, randomCoeff)
	}

	// Verify instruction
	if circuitData.ComponentConfig[20] {
		sum = c.verifyInstruction.Evaluate(sum, traces, randomCoeff)
	}

	// Blake context
	if circuitData.ComponentConfig[21] {
		sum = c.blakeRound.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[22] {
		sum = c.blakeG.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[23] {
		sum = c.blakeRoundSigma.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[24] {
		sum = c.tripleXor32.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[25] {
		sum = c.verifyBitwiseXor12.Evaluate(sum, traces, randomCoeff)
	}

	// Builtins
	if circuitData.ComponentConfig[26] {
		sum = c.addModBuiltin.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[27] {
		sum = c.bitwiseBuiltin.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[28] {
		sum = c.mulModBuiltin.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[29] {
		sum = c.pedersenBuiltin.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[30] {
		sum = c.poseidonBuiltin.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[31] {
		sum = c.rangeCheckBuiltin96.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[32] {
		sum = c.rangeCheckBuiltin128.Evaluate(sum, traces, randomCoeff)
	}

	// Pedersen context
	if circuitData.ComponentConfig[33] {
		sum = c.partialEcMul.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[34] {
		sum = c.pedersenPointsTable.Evaluate(sum, traces, randomCoeff)
	}

	// Poseidon context
	if circuitData.ComponentConfig[35] {
		sum = c.poseidon3PartialRoundsChain.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[36] {
		sum = c.poseidonFullRoundChain.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[37] {
		sum = c.cube252.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[38] {
		sum = c.poseidonRoundKeys.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[39] {
		sum = c.rangeCheckFelt252Width27.Evaluate(sum, traces, randomCoeff)
	}

	// Memory relations
	if circuitData.ComponentConfig[40] {
		sum = c.memoryAddressToID.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[41] {
		sum = c.memoryIDToBigBigComponents.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[42] {
		sum = c.memoryIDToBigSmallComponent.Evaluate(sum, traces, randomCoeff)
	}

	// Range check components
	if circuitData.ComponentConfig[43] {
		sum = c.rangeCheck6.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[44] {
		sum = c.rangeCheck8.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[45] {
		sum = c.rangeCheck11.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[46] {
		sum = c.rangeCheck12.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[47] {
		sum = c.rangeCheck18.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[48] {
		sum = c.rangeCheck19.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[49] {
		sum = c.rangeCheck43.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[50] {
		sum = c.rangeCheck44.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[51] {
		sum = c.rangeCheck54.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[52] {
		sum = c.rangeCheck99.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[53] {
		sum = c.rangeCheck725.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[54] {
		sum = c.rangeCheck3663.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[55] {
		sum = c.rangeCheck4444.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[56] {
		sum = c.rangeCheck33333.Evaluate(sum, traces, randomCoeff)
	}

	// Verify bitwise XOR components
	if circuitData.ComponentConfig[57] {
		sum = c.verifyBitwiseXor4.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[58] {
		sum = c.verifyBitwiseXor7.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[59] {
		sum = c.verifyBitwiseXor8.Evaluate(sum, traces, randomCoeff)
	}
	if circuitData.ComponentConfig[60] {
		sum = c.verifyBitwiseXor9.Evaluate(sum, traces, randomCoeff)
	}
	return sum
}
