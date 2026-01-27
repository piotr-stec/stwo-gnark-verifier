package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/HerodotusDev/stwo-gnark-verifier/verifier"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// GenericVerifierCircuit is the circuit for verifying with generic AIR support
type GenericVerifierCircuit struct {
	// StarkProof from proof.json
	Proof variables.StarkProof `gnark:",public"`
	// VerificationParams from params.json (part of public witness)
	Params variables.VerificationParams `gnark:",public"`
}

// Define defines the circuit for generic verification
func (c *GenericVerifierCircuit) Define(api frontend.API) error {
	verifierChip := verifier.NewVerifierChip(api)
	verifierChip.Verify(c.Proof, c.Params)
	return nil
}

func main() {
	// Parse command line flags
	proofPath := flag.String("proof", "proof.json", "Path to proof JSON file")
	paramsPath := flag.String("params", "params.json", "Path to params JSON file")
	flag.Parse()

	fmt.Println("╔════════════════════════════════════════════════════╗")
	fmt.Println("║   Stwo Gnark Verifier - Generic AIR Support       ║")
	fmt.Println("╚════════════════════════════════════════════════════╝")
	fmt.Println()

	// ╔══════════════════════════════════╗
	// ║         Load Proof Data          ║
	// ╚══════════════════════════════════╝
	fmt.Printf("Loading proof from: %s\n", *proofPath)
	proofRaw, err := loadStarkProofFromFile(*proofPath)
	if err != nil {
		fmt.Printf("Error loading proof: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓ Proof loaded successfully")

	// ╔══════════════════════════════════╗
	// ║    Load Verification Params      ║
	// ╚══════════════════════════════════╝
	fmt.Printf("Loading verification params from: %s\n", *paramsPath)
	paramsRaw, err := variables.ReadVerificationParams(*paramsPath)
	if err != nil {
		fmt.Printf("Error loading params: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓ Verification params loaded successfully")
	fmt.Printf("  - Components: %d\n", len(paramsRaw.ComponentParams))
	fmt.Printf("  - Tree roots: %d\n", len(paramsRaw.TreeRoots))
	fmt.Printf("  - Composition log degree bound: %d\n", paramsRaw.ComponentsCompositionLogDegreeBound)

	// ╔══════════════════════════════════╗
	// ║      Build Circuit Structures    ║
	// ╚══════════════════════════════════╝
	fmt.Println("\nBuilding circuit structures...")

	// Build proof for circuit (will be mutated during compilation)
	circuitProof := buildStarkProofFromRaw(proofRaw)

	// Build proof for witness (separate instance)
	witnessProof := buildStarkProofFromRaw(proofRaw)

	// Build verification params
	verificationParams := variables.BuildVerificationParams(paramsRaw)

	circuit := GenericVerifierCircuit{
		Proof:  circuitProof,
		Params: verificationParams,
	}
	assignment := GenericVerifierCircuit{
		Proof:  witnessProof,
		Params: verificationParams,
	}
	fmt.Println("✓ Circuit structures built")

	// ╔══════════════════════════════════╗
	// ║        Circuit Compilation       ║
	// ╚══════════════════════════════════╝
	fmt.Println("\nCompiling circuit...")
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Printf("Error in circuit compilation: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✓ Circuit compiled successfully\n")
	fmt.Printf("  - Constraints: %d\n", r1cs.GetNbConstraints())

	// ╔══════════════════════════════════╗
	// ║          Circuit Setup           ║
	// ╚══════════════════════════════════╝
	fmt.Println("\nRunning trusted setup...")
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		fmt.Printf("Error in setup: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓ Setup completed")

	// ╔══════════════════════════════════╗
	// ║        Witness Generation        ║
	// ╚══════════════════════════════════╝
	fmt.Println("\nGenerating witness...")
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Printf("Error in witness generation: %v\n", err)
		os.Exit(1)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		fmt.Printf("Error in public witness generation: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓ Witness generated")

	// ╔══════════════════════════════════╗
	// ║         Proof Generation         ║
	// ╚══════════════════════════════════╝
	fmt.Println("\nGenerating Groth16 proof...")
	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		fmt.Printf("Error in proof generation: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓ Groth16 proof generated")

	// ╔══════════════════════════════════╗
	// ║           Verification           ║
	// ╚══════════════════════════════════╝
	fmt.Println("\nVerifying Groth16 proof...")
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Printf("✗ Verification failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✓ Verification successful!")
	fmt.Println()
	fmt.Println("╔════════════════════════════════════════════════════╗")
	fmt.Println("║              Verification Complete ✓               ║")
	fmt.Println("╚════════════════════════════════════════════════════╝")
}

// Helper function to load StarkProof from JSON
func loadStarkProofFromFile(path string) (*variables.StarkProofRaw, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var proof variables.StarkProofRaw
	if err := json.Unmarshal(data, &proof); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	return &proof, nil
}

func buildStarkProofFromRaw(raw *variables.StarkProofRaw) variables.StarkProof {
	return variables.BuildStarkProof(raw)
}
