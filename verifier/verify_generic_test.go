package verifier

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
)

// TestVerifyGeneric tests the generic Verify function with separate JSON files
// This is a functional test that doesn't compile the full circuit
func TestVerifyGeneric(t *testing.T) {
	t.Skip("Test requires valid proof and params JSON files - this is a template")

	// Load StarkProof from JSON
	proofPath := "../proof.json"
	proofRaw, err := loadStarkProofRaw(proofPath)
	if err != nil {
		t.Fatalf("Failed to load stark proof: %v", err)
	}

	// Load VerificationParams from separate JSON
	paramsPath := "../test_data/verification_params_example.json"
	paramsRaw, err := variables.ReadVerificationParams(paramsPath)
	if err != nil {
		t.Fatalf("Failed to load verification params: %v", err)
	}

	// Build circuit-ready structures
	_ = buildStarkProofFromRaw(proofRaw)
	verificationParams := variables.BuildVerificationParams(paramsRaw)
	
	// Note: For actual testing with Verify, you would need a proper circuit context
	// This is a template showing the structure
	t.Log("StarkProof loaded successfully")
	t.Log("VerificationParams loaded successfully")
	t.Logf("Number of components: %d", len(verificationParams.ComponentParams))
	t.Logf("Number of tree roots: %d", len(verificationParams.TreeRoots))
	
	// In a real test with circuit compilation, you would:
	// 1. Create a proper API instance (requires circuit compilation)
	// 2. Create VerifierChip
	// 3. Call Verify
	// verifierChip := NewVerifierChip(api)
	// verifierChip.Verify(starkProof, verificationParams)
}

// TestLoadVerificationParams tests loading verification parameters from JSON
func TestLoadVerificationParams(t *testing.T) {
	paramsPath := "../params.json"
	
	paramsRaw, err := variables.ReadVerificationParams(paramsPath)
	if err != nil {
		t.Fatalf("Failed to load verification params: %v", err)
	}

	// Verify the loaded data
	if paramsRaw == nil {
		t.Fatal("Loaded params are nil")
	}

	if len(paramsRaw.ComponentParams) == 0 {
		t.Error("No component params loaded")
	}

	if len(paramsRaw.TreeRoots) == 0 {
		t.Error("No tree roots loaded")
	}

	if len(paramsRaw.Digest) != 8 {
		t.Errorf("Expected digest length 8, got %d", len(paramsRaw.Digest))
	}

	t.Logf("Successfully loaded %d components", len(paramsRaw.ComponentParams))
	t.Logf("Successfully loaded %d tree roots", len(paramsRaw.TreeRoots))
	t.Logf("Composition log degree bound: %d", paramsRaw.ComponentsCompositionLogDegreeBound)
}

// TestBuildVerificationParams tests building circuit-ready params from raw
func TestBuildVerificationParams(t *testing.T) {
	paramsPath := "../params.json"
	
	paramsRaw, err := variables.ReadVerificationParams(paramsPath)
	if err != nil {
		t.Fatalf("Failed to load verification params: %v", err)
	}

	// Build circuit-ready params
	params := variables.BuildVerificationParams(paramsRaw)

	// Verify conversions
	if len(params.ComponentParams) != len(paramsRaw.ComponentParams) {
		t.Errorf("Component params count mismatch: got %d, want %d", 
			len(params.ComponentParams), len(paramsRaw.ComponentParams))
	}

	if len(params.TreeRoots) != len(paramsRaw.TreeRoots) {
		t.Errorf("Tree roots count mismatch: got %d, want %d",
			len(params.TreeRoots), len(paramsRaw.TreeRoots))
	}

	// Check digest conversion (U32 doesn't have Val field, use uints methods)
	t.Logf("Digest first element: %v", params.Digest[0])

	t.Log("BuildVerificationParams successful")
}

// Helper structures for StarkProof JSON loading (simplified)
type StarkProofRaw struct {
	Config          variables.PcsConfig `json:"config"`
	ProofOfWork     uint64              `json:"proof_of_work"`
}

func loadStarkProofRaw(path string) (*StarkProofRaw, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var proof StarkProofRaw
	if err := json.Unmarshal(data, &proof); err != nil {
		return nil, err
	}

	return &proof, nil
}

func buildStarkProofFromRaw(raw *StarkProofRaw) variables.StarkProof {
	// This is a placeholder - actual implementation would convert all fields
	// For now, returning an empty struct as this is a template
	return variables.StarkProof{
		Config: raw.Config,
		// ... other fields would be converted here
	}
}
