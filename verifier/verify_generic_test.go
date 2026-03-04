package verifier

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

// TestVerifyGeneric tests the generic Verify function with separate JSON files
func TestVerifyGeneric(t *testing.T) {
	// Load StarkProof from JSON
	proofPath := "../example_data/fibonacci_public_inputs/fibonacci_pub_inputs_proof.json"
	proofRaw, err := loadStarkProofRaw(proofPath)
	if err != nil {
		t.Fatalf("Failed to load stark proof: %v", err)
	}

	// Load VerificationParams from JSON
	paramsPath := "../example_data/fibonacci_public_inputs/fibonacci_pub_inputs_params.json"
	paramsRaw, err := variables.ReadVerificationParams(paramsPath)
	if err != nil {
		t.Fatalf("Failed to load verification params: %v", err)
	}

	shapePath := "../example_data/fibonacci_public_inputs/fibonacci_pub_inputs_shape.json"
	shapeRaw, err := variables.ReadCircuitShape(shapePath)
	if err != nil {
		t.Fatalf("Failed to load circuit shape: %v", err)
	}
	// Build circuit-ready structures
	starkProof := variables.BuildStarkProof(proofRaw)
	verificationParamsCircuit := variables.BuildVerificationParams(paramsRaw)
	verificationParamsAssignment := variables.BuildVerificationParams(paramsRaw)
	circuitData := variables.BuildCircuitData(shapeRaw)

	// Load public inputs
	publicInputsPath := "../example_data/fibonacci_public_inputs/fibonacci_pub_inputs.json"
	publicInputsRaw, err := loadFibonacciPublicInputsRaw(publicInputsPath)
	if err != nil {
		t.Fatalf("Failed to load public inputs: %v", err)
	}
	publicInputs := BuildFibonacciPublicInputs(publicInputsRaw)
	circuit := GenericVerifierCircuit{
		Proof:  starkProof,
		Params: verificationParamsCircuit,
		Shape:  circuitData,
		LogSize:       publicInputs.LogSize,
		InitialA:      publicInputs.InitialA,
		InitialB:      publicInputs.InitialB,
		TargetValue:   publicInputs.ExpectedValue,
	}

	assignment := GenericVerifierCircuit{
		Proof:  starkProof,
		Params: verificationParamsAssignment,
		Shape:  circuitData,
		LogSize:       publicInputs.LogSize,
		InitialA:      publicInputs.InitialA,
		InitialB:      publicInputs.InitialB,
		TargetValue:   publicInputs.ExpectedValue,
	}

	// Use IsSolved which just checks if constraints are satisfied without serialization
	err = test.IsSolved(&circuit, &assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("Circuit constraints not satisfied: %v", err)
	}

	t.Log("✓ Circuit constraints satisfied - proof is valid!")
}

// GenericVerifierCircuit is a wrapper for testing
// Fibonacci example thath proves that i know N that initial value A and B will produce TargetValue after N steps.
// This is just a simple example to test the generic verification logic with public inputs.
type GenericVerifierCircuit struct {
	Proof       variables.StarkProof         `gnark:"-"`
	Params      variables.VerificationParams `gnark:"-"`
	Shape       variables.CircuitData        `gnark:"-"`
	LogSize     uints.U64                    `gnark:",public"`
	InitialA    uints.U64                    `gnark:",public"`
	InitialB    uints.U64                    `gnark:",public"`
	TargetValue uints.U64                    `gnark:",public"`
}

func (c *GenericVerifierCircuit) Define(api frontend.API) error {
	verifierChip := NewVerifierChip(api)
	verifierChip.Verify(c.Proof, c.Params, c.Shape, []uints.U64{c.LogSize, c.InitialA, c.InitialB, c.TargetValue})
	return nil
}

func loadStarkProofRaw(path string) (*variables.StarkProofRaw, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var proof variables.StarkProofRaw
	if err := json.Unmarshal(data, &proof); err != nil {
		return nil, err
	}

	return &proof, nil
}

// FibonacciPublicInputsRaw represents the raw public inputs from JSON
type FibonacciPublicInputsRaw struct {
	LogSize       uint64 `json:"logSize"`
	InitialA      uint64 `json:"initialA"`
	InitialB      uint64 `json:"initialB"`
	ExpectedValue uint64 `json:"expectedValue"`
}

// FibonacciPublicInputs represents the public inputs for the Fibonacci circuit
type FibonacciPublicInputs struct {
	LogSize       uints.U64
	InitialA      uints.U64
	InitialB      uints.U64
	ExpectedValue uints.U64
}

// loadFibonacciPublicInputsRaw loads raw public inputs from a JSON file
func loadFibonacciPublicInputsRaw(path string) (*FibonacciPublicInputsRaw, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var raw FibonacciPublicInputsRaw
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	return &raw, nil
}

// BuildFibonacciPublicInputs converts raw public inputs to circuit-ready types
func BuildFibonacciPublicInputs(raw *FibonacciPublicInputsRaw) *FibonacciPublicInputs {
	return &FibonacciPublicInputs{
		LogSize:       uints.NewU64(raw.LogSize),
		InitialA:      uints.NewU64(raw.InitialA),
		InitialB:      uints.NewU64(raw.InitialB),
		ExpectedValue: uints.NewU64(raw.ExpectedValue),
	}
}
