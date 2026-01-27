package verifier

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

// TestVerifyGeneric tests the generic Verify function with separate JSON files
func TestVerifyGeneric(t *testing.T) {
	// Load StarkProof from JSON
	proofPath := "../proof.json"
	proofRaw, err := loadStarkProofRaw(proofPath)
	if err != nil {
		t.Fatalf("Failed to load stark proof: %v", err)
	}

	// Load VerificationParams from JSON
	paramsPath := "../params.json"
	paramsRaw, err := variables.ReadVerificationParams(paramsPath)
	if err != nil {
		t.Fatalf("Failed to load verification params: %v", err)
	}

	// Build circuit-ready structures
	starkProof := variables.BuildStarkProof(proofRaw)
	verificationParamsCircuit := variables.BuildVerificationParams(paramsRaw)
	verificationParamsAssignment := variables.BuildVerificationParams(paramsRaw)

	circuit := GenericVerifierCircuit{
		Proof:  starkProof,
		Params: verificationParamsCircuit,
	}

	assignment := GenericVerifierCircuit{
		Proof:  starkProof,
		Params: verificationParamsAssignment,
	}

	// Use IsSolved which just checks if constraints are satisfied without serialization
	err = test.IsSolved(&circuit, &assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("Circuit constraints not satisfied: %v", err)
	}

	t.Log("✓ Circuit constraints satisfied - proof is valid!")
}

// GenericVerifierCircuit is a wrapper for testing
type GenericVerifierCircuit struct {
	Proof  variables.StarkProof         `gnark:",public"`
	Params variables.VerificationParams `gnark:",public"`
}

func (c *GenericVerifierCircuit) Define(api frontend.API) error {
	verifierChip := NewVerifierChip(api)
	verifierChip.Verify(c.Proof, c.Params)
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
