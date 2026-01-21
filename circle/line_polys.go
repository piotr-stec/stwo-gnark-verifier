package circle

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/std/math/uints"
)

// LinePoly represents a line polynomial (used for FRI last layer polynomial)
type LinePoly struct {
	Coeffs  []m31.QM31
	LogSize uints.U8
}

// EvalAt evaluates the line polynomial at a single point.
// This is based on the Rust implementation:
// pub fn eval_at_point(&self, mut x: SecureField) -> SecureField
func (lp LinePoly) EvalAt(qm31Chip *m31.QM31Chip, x m31.QM31) m31.QM31 {
	// logSize is log2(len(coeffs))
	// We need to compute doublings for each level of recursion
	n := len(lp.Coeffs)
	if n == 0 {
		return qm31Chip.Zero()
	}

	// Calculate logSize from the number of coefficients
	logSize := 0
	temp := n
	for temp > 1 {
		logSize++
		temp >>= 1
	}

	// Build doublings: [x, x^2, x^4, x^8, ...]
	// where x^2 = double_x(x) = 2*x^2 - 1
	doublings := make([]m31.QM31, logSize)
	currentX := x
	for i := 0; i < logSize; i++ {
		doublings[i] = currentX
		// double_x: 2*x^2 - 1
		currentX = doubleX(qm31Chip, currentX)
	}

	// Fold the coefficients using the doublings
	return fold(qm31Chip, lp.Coeffs, doublings)
}

// doubleX implements CirclePoint::double_x: 2*x^2 - 1
func doubleX(qm31Chip *m31.QM31Chip, x m31.QM31) m31.QM31 {
	xSquared := qm31Chip.Mul(x, x)
	doubled := qm31Chip.Add(xSquared, xSquared)  // 2*x^2
	return qm31Chip.Sub(doubled, qm31Chip.One()) // 2*x^2 - 1
}

// fold recursively folds values in O(n) by a hierarchical application of folding factors.
// This implements the Rust fold function:
// pub fn fold<F: Field, E: ExtensionOf<F>>(values: &[F], folding_factors: &[E]) -> E
//
// The folding works as follows for n=8 values with folding_factors=[x,y,z]:
//
//	          n2=n1+x*n2
//	      /               \
//	n1=n3+y*n4          n2=n5+y*n6
//	 /      \            /      \
//
// n3=a+z*b  n4=c+z*d  n5=e+z*f  n6=g+z*h
//
//	 /  \      /  \      /  \      /  \
//	a    b    c    d    e    f    g    h
func fold(qm31Chip *m31.QM31Chip, values []m31.QM31, foldingFactors []m31.QM31) m31.QM31 {
	n := len(values)

	// Base case: single value
	if n == 1 {
		return values[0]
	}

	// Verify that n is a power of two and matches folding factors length
	if n != (1 << len(foldingFactors)) {
		panic("fold: values length must equal 2^(folding_factors length)")
	}

	// Split values in half
	mid := n / 2
	lhsValues := values[:mid]
	rhsValues := values[mid:]

	// Split folding factors (first factor is used at this level)
	foldingFactor := foldingFactors[0]
	remainingFactors := foldingFactors[1:]

	// Recursively fold left and right halves
	lhsVal := fold(qm31Chip, lhsValues, remainingFactors)
	rhsVal := fold(qm31Chip, rhsValues, remainingFactors)

	// Combine: lhs + rhs * folding_factor
	rhsScaled := qm31Chip.Mul(rhsVal, foldingFactor)
	return qm31Chip.Add(lhsVal, rhsScaled)
}
