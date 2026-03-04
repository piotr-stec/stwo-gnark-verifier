package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"

	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/HerodotusDev/stwo-gnark-verifier/verifier"
	"github.com/consensys/gnark-crypto/ecc"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/solidity"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/uints"
)

// GenericVerifierCircuit is the circuit for verifying with generic AIR support
// Fibonacci example that proves that initial value A and B will produce TargetValue after N steps.
type GenericVerifierCircuit struct {
	Proof       variables.StarkProof         `gnark:"-"`
	Params      variables.VerificationParams `gnark:"-"`
	Shape       variables.CircuitData        `gnark:"-"`
	LogSize     uints.U64                    `gnark:",public"`
	InitialA    uints.U64                    `gnark:",public"`
	InitialB    uints.U64                    `gnark:",public"`
	TargetValue uints.U64                    `gnark:",public"`
}

// Define defines the circuit for generic verification
func (c *GenericVerifierCircuit) Define(api frontend.API) error {
	verifierChip := verifier.NewVerifierChip(api)
	verifierChip.Verify(c.Proof, c.Params, c.Shape, []uints.U64{c.LogSize, c.InitialA, c.InitialB, c.TargetValue})
	return nil
}

func main() {
	// Parse command line flags
	proofPath := flag.String("proof", "proof.json", "Path to proof JSON file")
	paramsPath := flag.String("params", "params.json", "Path to params JSON file")
	shapePath := flag.String("shape", "", "Path to shape JSON file (optional, uses default fixture if not provided)")
	publicInputsPath := flag.String("public-inputs", "public_inputs.json", "Path to public inputs JSON file")
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
	// ║      Load Circuit Shape          ║
	// ╚══════════════════════════════════╝
	var shapeRaw *variables.CircuitShapeRaw

	fmt.Printf("Loading circuit shape from: %s\n", *shapePath)
	shapeRaw, err = variables.ReadCircuitShape(*shapePath)
	if err != nil {
		fmt.Printf("Error loading shape: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓ Circuit shape loaded successfully")

	// ╔══════════════════════════════════╗
	// ║      Load Public Inputs          ║
	// ╚══════════════════════════════════╝
	fmt.Printf("Loading public inputs from: %s\n", *publicInputsPath)
	publicInputsRaw, err := loadFibonacciPublicInputsRaw(*publicInputsPath)
	if err != nil {
		fmt.Printf("Error loading public inputs: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓ Public inputs loaded successfully")
	fmt.Printf("  - LogSize: %d\n", publicInputsRaw.LogSize)
	fmt.Printf("  - InitialA: %d\n", publicInputsRaw.InitialA)
	fmt.Printf("  - InitialB: %d\n", publicInputsRaw.InitialB)
	fmt.Printf("  - ExpectedValue: %d\n", publicInputsRaw.ExpectedValue)

	// ╔══════════════════════════════════╗
	// ║      Build Circuit Structures    ║
	// ╚══════════════════════════════════╝
	fmt.Println("\nBuilding circuit structures...")

	// Build proof for circuit (will be mutated during compilation)
	circuitProof := buildStarkProofFromRaw(proofRaw)

	// Build proof for witness (separate instance)
	witnessProof := buildStarkProofFromRaw(proofRaw)

	// Build verification params (two separate instances - one for circuit, one for witness)
	circuitParams := variables.BuildVerificationParams(paramsRaw)
	witnessParams := variables.BuildVerificationParams(paramsRaw)
	circuitData := variables.BuildCircuitData(shapeRaw)

	// Build public inputs
	publicInputs := BuildFibonacciPublicInputs(publicInputsRaw)

	circuit := GenericVerifierCircuit{
		Proof:       circuitProof,
		Params:      circuitParams,
		Shape:       circuitData,
		LogSize:     publicInputs.LogSize,
		InitialA:    publicInputs.InitialA,
		InitialB:    publicInputs.InitialB,
		TargetValue: publicInputs.ExpectedValue,
	}
	assignment := GenericVerifierCircuit{
		Proof:       witnessProof,
		Params:      witnessParams,
		Shape:       circuitData,
		LogSize:     publicInputs.LogSize,
		InitialA:    publicInputs.InitialA,
		InitialB:    publicInputs.InitialB,
		TargetValue: publicInputs.ExpectedValue,
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

	// Export Solidity verifier
	fmt.Println("\nExporting Solidity verifier...")
	solidityFile, err := os.Create("Verifier.sol")
	if err != nil {
		fmt.Printf("Error creating Solidity file: %v\n", err)
		os.Exit(1)
	}
	defer solidityFile.Close()

	err = vk.ExportSolidity(solidityFile)
	if err != nil {
		fmt.Printf("Error exporting Solidity verifier: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓ Solidity verifier exported to Verifier.sol")

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
	proof, err := groth16.Prove(r1cs, pk, witness, solidity.WithProverTargetSolidityVerifier(backend.GROTH16))
	if err != nil {
		fmt.Printf("Error in proof generation: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓ Groth16 proof generated")

	// ╔══════════════════════════════════╗
	// ║         Export Proof Data        ║
	// ╚══════════════════════════════════╝
	fmt.Println("\nExporting proof and witness for Solidity...")
	fmt.Printf("Proof: %v\n", proof)
	// Write to raw proof:
	bn254Proof := proof.(*groth16_bn254.Proof)
	bn254ProofBytes := bn254Proof.MarshalSolidity()
	fmt.Printf("Proof bytes (hex): %s\n", hex.EncodeToString(bn254ProofBytes))

	fmt.Printf("Proof bytes raw: %v\n", bn254ProofBytes)
	// Export using proper gnark serialization
	err = exportSolidityProofAndWitness(proof, publicWitness)
	if err != nil {
		fmt.Printf("Error exporting Solidity data: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓ Proof and witness exported to proof_solidity.json and witness_solidity.json")

	// Export raw proof as hex
	err = exportProofAsHex(proof)
	if err != nil {
		fmt.Printf("Error exporting proof as hex: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓ Proof exported as hex to proof_raw.hex")

	// ╔══════════════════════════════════╗
	// ║           Verification           ║
	// ╚══════════════════════════════════╝
	fmt.Println("\nVerifying Groth16 proof...")
	err = groth16.Verify(proof, vk, publicWitness, solidity.WithVerifierTargetSolidityVerifier(backend.GROTH16))
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

// SolidityProof represents proof data for Solidity verifier
type SolidityProof struct {
	Proof         [8]string `json:"proof"`
	Commitments   [2]string `json:"commitments"`
	CommitmentPok [2]string `json:"commitmentPok"`
}

// exportSolidityProofAndWitness exports proof and witness in JSON format for Solidity
func exportSolidityProofAndWitness(proof groth16.Proof, wit witness.Witness) error {
	// Convert proof to BN254 type
	g16proof, ok := proof.(*groth16_bn254.Proof)
	if !ok {
		return fmt.Errorf("expected groth16_bn254.Proof, got %T", proof)
	}

	// Extract proof components in Solidity format (as strings to avoid formatting issues)
	solProof := SolidityProof{
		Proof: [8]string{
			g16proof.Ar.X.BigInt(new(big.Int)).String(),
			g16proof.Ar.Y.BigInt(new(big.Int)).String(),
			g16proof.Bs.X.A1.BigInt(new(big.Int)).String(),
			g16proof.Bs.X.A0.BigInt(new(big.Int)).String(),
			g16proof.Bs.Y.A1.BigInt(new(big.Int)).String(),
			g16proof.Bs.Y.A0.BigInt(new(big.Int)).String(),
			g16proof.Krs.X.BigInt(new(big.Int)).String(),
			g16proof.Krs.Y.BigInt(new(big.Int)).String(),
		},
		Commitments: [2]string{
			g16proof.Commitments[0].X.BigInt(new(big.Int)).String(),
			g16proof.Commitments[0].Y.BigInt(new(big.Int)).String(),
		},
		CommitmentPok: [2]string{
			g16proof.CommitmentPok.X.BigInt(new(big.Int)).String(),
			g16proof.CommitmentPok.Y.BigInt(new(big.Int)).String(),
		},
	}

	// Export proof to JSON
	proofJSON, err := json.MarshalIndent(solProof, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal proof: %w", err)
	}
	err = os.WriteFile("proof_solidity.json", proofJSON, 0644)
	if err != nil {
		return fmt.Errorf("failed to write proof file: %w", err)
	}

	// Extract witness values as string array (to avoid formatting issues)
	// wit is already public witness, extract its vector representation
	witVec := wit.Vector().(fr_bn254.Vector)
	witnessValues := make([]string, len(witVec))
	for i := range witVec {
		bi := new(big.Int)
		witVec[i].BigInt(bi)
		witnessValues[i] = bi.String()
	}

	// Export witness as JSON array
	witnessJSON, err := json.MarshalIndent(witnessValues, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal witness: %w", err)
	}

	err = os.WriteFile("witness_solidity.json", witnessJSON, 0644)
	if err != nil {
		return fmt.Errorf("failed to write witness file: %w", err)
	}

	return nil
}

// exportProofAsHex exports the proof as a single hex string (uncompressed format for Solidity)
func exportProofAsHex(proof groth16.Proof) error {
	// Convert proof to BN254 type
	g16proof, ok := proof.(*groth16_bn254.Proof)
	if !ok {
		return fmt.Errorf("expected groth16_bn254.Proof, got %T", proof)
	}

	// Debug: print commitment and commitmentPok values
	fmt.Println("\nDebug - Proof components:")
	fmt.Printf("Ar: X=%s, Y=%s\n", g16proof.Ar.X.BigInt(new(big.Int)).String(), g16proof.Ar.Y.BigInt(new(big.Int)).String())
	fmt.Printf("Krs: X=%s, Y=%s\n", g16proof.Krs.X.BigInt(new(big.Int)).String(), g16proof.Krs.Y.BigInt(new(big.Int)).String())
	if len(g16proof.Commitments) > 0 {
		fmt.Printf("Commitment[0]: X=%s, Y=%s\n",
			g16proof.Commitments[0].X.BigInt(new(big.Int)).String(),
			g16proof.Commitments[0].Y.BigInt(new(big.Int)).String())
	}
	fmt.Printf("CommitmentPok: X=%s, Y=%s\n",
		g16proof.CommitmentPok.X.BigInt(new(big.Int)).String(),
		g16proof.CommitmentPok.Y.BigInt(new(big.Int)).String())

	var buf bytes.Buffer

	// Write Ar (G1 point: X, Y) - 2 * 32 bytes
	buf.Write(g16proof.Ar.X.BigInt(new(big.Int)).FillBytes(make([]byte, 32)))
	buf.Write(g16proof.Ar.Y.BigInt(new(big.Int)).FillBytes(make([]byte, 32)))

	// Write Bs (G2 point: X.A1, X.A0, Y.A1, Y.A0) - 4 * 32 bytes
	buf.Write(g16proof.Bs.X.A1.BigInt(new(big.Int)).FillBytes(make([]byte, 32)))
	buf.Write(g16proof.Bs.X.A0.BigInt(new(big.Int)).FillBytes(make([]byte, 32)))
	buf.Write(g16proof.Bs.Y.A1.BigInt(new(big.Int)).FillBytes(make([]byte, 32)))
	buf.Write(g16proof.Bs.Y.A0.BigInt(new(big.Int)).FillBytes(make([]byte, 32)))

	// Write Krs (G1 point: X, Y) - 2 * 32 bytes
	buf.Write(g16proof.Krs.X.BigInt(new(big.Int)).FillBytes(make([]byte, 32)))
	buf.Write(g16proof.Krs.Y.BigInt(new(big.Int)).FillBytes(make([]byte, 32)))

	// Write commitment count (4 bytes, big-endian)
	commitmentCount := len(g16proof.Commitments)
	commitmentCountBytes := make([]byte, 4)
	commitmentCountBytes[0] = 0
	commitmentCountBytes[1] = 0
	commitmentCountBytes[2] = 0
	commitmentCountBytes[3] = byte(commitmentCount)
	buf.Write(commitmentCountBytes)

	// Write commitments (each is G1 point: X, Y)
	for _, commitment := range g16proof.Commitments {
		buf.Write(commitment.X.BigInt(new(big.Int)).FillBytes(make([]byte, 32)))
		buf.Write(commitment.Y.BigInt(new(big.Int)).FillBytes(make([]byte, 32)))
	}

	// Write commitmentPok (G1 point: X, Y)
	buf.Write(g16proof.CommitmentPok.X.BigInt(new(big.Int)).FillBytes(make([]byte, 32)))
	buf.Write(g16proof.CommitmentPok.Y.BigInt(new(big.Int)).FillBytes(make([]byte, 32)))

	// Convert to hex string
	hexString := hex.EncodeToString(buf.Bytes())

	// Write to file
	err := os.WriteFile("proof_raw.hex", []byte(hexString), 0644)
	if err != nil {
		return fmt.Errorf("failed to write hex file: %w", err)
	}

	return nil
}
