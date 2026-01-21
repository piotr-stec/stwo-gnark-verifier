package circle

import (
	"testing"

	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type SecureCirclePolyEvalCircuit struct {
	Poly   SecureCirclePoly
	Point  Point
	Result m31.QM31 `gnark:",public"`
}

func (circuit *SecureCirclePolyEvalCircuit) Define(api frontend.API) error {
	m31Chip := m31.NewM31Chip(api)
	qm31Chip := m31.NewQM31Chip(m31Chip)

	result := circuit.Poly.EvalAt(qm31Chip, circuit.Point)

	qm31Chip.AssertEqual(result, circuit.Result)

	return nil
}

func TestSecureCirclePolyEval(t *testing.T) {
	// Test: Secure Circle Polynomial evaluation
	// Matches Rust test: test_secure_circle_poly_single_coord
	// 4 coordinate polynomials each with 4 coefficients
	// Point: x=5, y=8 (as SecureField, so (5,0,0,0) and (8,0,0,0))
	
	// Coordinate polynomial 0: coefficients [1, 2, 3, 4]
	coeffs0 := []m31.M31{
		m31.NewM31Unchecked(1),
		m31.NewM31Unchecked(2),
		m31.NewM31Unchecked(3),
		m31.NewM31Unchecked(4),
	}
	
	// Coordinate polynomial 1: coefficients [17, 22, 2323, 1212]
	coeffs1 := []m31.M31{
		m31.NewM31Unchecked(17),
		m31.NewM31Unchecked(22),
		m31.NewM31Unchecked(2323),
		m31.NewM31Unchecked(1212),
	}
	
	// Coordinate polynomial 2: coefficients [2323, 22, 1212, 1212]
	coeffs2 := []m31.M31{
		m31.NewM31Unchecked(2323),
		m31.NewM31Unchecked(22),
		m31.NewM31Unchecked(1212),
		m31.NewM31Unchecked(1212),
	}
	
	// Coordinate polynomial 3: coefficients [17, 22, 2323, 1212]
	coeffs3 := []m31.M31{
		m31.NewM31Unchecked(17),
		m31.NewM31Unchecked(22),
		m31.NewM31Unchecked(2323),
		m31.NewM31Unchecked(1212),
	}
	
	poly := NewSecureCirclePoly(coeffs0, coeffs1, coeffs2, coeffs3)
	
	// Evaluation point: CirclePoint with x=5, y=8
	// In QM31 format: x=(5,0,0,0), y=(8,0,0,0)
	point := Point{
		X: m31.NewQM31Unchecked(5, 0, 0, 0),
		Y: m31.NewQM31Unchecked(8, 0, 0, 0),
	}
	
	// Expected result from Rust test output:
	// Result of evaluation: (192 + 60288i) + (57039 + 60288i)u
	// In QM31 format: (192, 60288, 57039, 60288)
	// This represents: (192 + 60288*i) + (57039 + 60288*i)*u
	// Where i is the imaginary unit for CM31 and u is the extension for QM31
	expectedResult := m31.NewQM31Unchecked(192, 60288, 57039, 60288)
	
	circuit := &SecureCirclePolyEvalCircuit{
		Poly:   poly,
		Point:  point,
		Result: expectedResult,
	}
	
	err := test.IsSolved(circuit, circuit, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("Circuit failed: %v", err)
	}
	
	t.Logf("✓ SecureCirclePoly evaluation successful")
	t.Logf("  Coeffs0: [1, 2, 3, 4]")
	t.Logf("  Coeffs1: [17, 22, 2323, 1212]")
	t.Logf("  Coeffs2: [2323, 22, 1212, 1212]")
	t.Logf("  Coeffs3: [17, 22, 2323, 1212]")
	t.Logf("  Point: x=(5,0,0,0), y=(8,0,0,0)")
	t.Logf("  Result: (192, 60288, 57039, 60288)")
	t.Logf("  Expected from Rust: (192 + 60288i) + (57039 + 60288i)u ✓")
}