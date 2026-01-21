package circle

import (
	"testing"

	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

type LinePolyEvalCircuit struct {
	Poly   LinePoly
	X      m31.QM31
	Result m31.QM31 `gnark:",public"`
}

func (circuit *LinePolyEvalCircuit) Define(api frontend.API) error {
	m31Chip := m31.NewM31Chip(api)
	qm31Chip := m31.NewQM31Chip(m31Chip)

	result := circuit.Poly.EvalAt(qm31Chip, circuit.X)

	qm31Chip.AssertEqual(result, circuit.Result)

	return nil
}

func TestLinePolyEval(t *testing.T) {
	// Test: Polynomial with 4 coefficients [1, 2, 3, 4]
	// LogSize = 2 (because 2^2 = 4 coefficients)
	// Evaluate at x = 5

	// Coefficients: [1, 2, 3, 4]
	coeffs := []m31.QM31{
		m31.NewQM31Unchecked(1, 0, 0, 0),
		m31.NewQM31Unchecked(2, 0, 0, 0),
		m31.NewQM31Unchecked(3, 0, 0, 0),
		m31.NewQM31Unchecked(4, 0, 0, 0),
	}

	poly := LinePoly{
		Coeffs:  coeffs,
		LogSize: uints.NewU8(2), // log2(4) = 2
	}

	// Evaluate at x = 5
	x := m31.NewQM31Unchecked(5, 0, 0, 0)

	// Manual calculation to verify in Rust:
	// 1. Build doublings:
	//    doublings[0] = 5
	//    doublings[1] = double_x(5) = 2*5^2 - 1 = 2*25 - 1 = 49
	//
	// 2. Fold recursively with doublings [5, 49]:
	//    Level 0: fold([1,2], [49]) = 1 + 2*49 = 1 + 98 = 99
	//    Level 0: fold([3,4], [49]) = 3 + 4*49 = 3 + 196 = 199
	//    Level 1: fold([99,199], [5]) = 99 + 199*5 = 99 + 995 = 1094
	//
	// Expected result: 1094
	expectedResult := m31.NewQM31Unchecked(1094, 0, 0, 0)

	circuit := &LinePolyEvalCircuit{
		Poly:   poly,
		X:      x,
		Result: expectedResult,
	}

	err := test.IsSolved(circuit, circuit, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("Circuit failed: %v", err)
	}

	t.Logf("✓ LinePoly evaluation successful")
	t.Logf("  Coefficients: [1, 2, 3, 4]")
	t.Logf("  LogSize: 2")
	t.Logf("  Evaluation point x: 5")
	t.Logf("  Result: 1094")
}
