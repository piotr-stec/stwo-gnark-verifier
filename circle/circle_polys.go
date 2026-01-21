package circle

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
)

// SecureCirclePoly represents a secure circle polynomial
// Equivalent to Rust SecureCirclePoly<B: ColumnOps<BaseField>>
// Contains 4 circle polynomials representing a polynomial over SecureField (QM31)
type SecureCirclePoly struct {
	// Each coefficients array stores M31 values in FFT basis (bit-reversed order)
	Coeffs0 []m31.M31 // M31 coefficients for polynomial 0
	Coeffs1 []m31.M31 // M31 coefficients for polynomial 1
	Coeffs2 []m31.M31 // M31 coefficients for polynomial 2
	Coeffs3 []m31.M31 // M31 coefficients for polynomial 3
}

// NewSecureCirclePoly creates a new secure circle polynomial
func NewSecureCirclePoly(coeffs0, coeffs1, coeffs2, coeffs3 []m31.M31) SecureCirclePoly {
	return SecureCirclePoly{
		Coeffs0: coeffs0,
		Coeffs1: coeffs1,
		Coeffs2: coeffs2,
		Coeffs3: coeffs3,
	}
}

// EvalAt evaluates the secure polynomial at a given circle point
// Equivalent to Rust SecureCirclePoly::eval_at_point()
// Evaluates each coordinate polynomial and combines using fromPartialEvals
func (p SecureCirclePoly) EvalAt(qm31Chip *m31.QM31Chip, point Point) m31.QM31 {
	// Evaluate each coordinate polynomial at the point
	evals := [4]m31.QM31{
		evalCirclePolyAtPoint(qm31Chip, p.Coeffs0, point),
		evalCirclePolyAtPoint(qm31Chip, p.Coeffs1, point),
		evalCirclePolyAtPoint(qm31Chip, p.Coeffs2, point),
		evalCirclePolyAtPoint(qm31Chip, p.Coeffs3, point),
	}

	// Combine evaluations using SecureField::from_partial_evals
	return qm31Chip.FromPartialEvals(evals[0], evals[1], evals[2], evals[3])
}

// EvalColumnsAt evaluates each coordinate polynomial separately
// Equivalent to Rust SecureCirclePoly::eval_columns_at_point()
func (p SecureCirclePoly) EvalColumnsAt(qm31Chip *m31.QM31Chip, point Point) [4]m31.QM31 {
	return [4]m31.QM31{
		evalCirclePolyAtPoint(qm31Chip, p.Coeffs0, point),
		evalCirclePolyAtPoint(qm31Chip, p.Coeffs1, point),
		evalCirclePolyAtPoint(qm31Chip, p.Coeffs2, point),
		evalCirclePolyAtPoint(qm31Chip, p.Coeffs3, point),
	}
}

// evalCirclePolyAtPoint evaluates a single circle polynomial at a point
// Implementation of CpuBackend::eval_at_point for circle polynomials
// Uses hierarchical folding with doubling sequence: [y, x, 2x²-1, 2(2x²-1)²-1, ...]
func evalCirclePolyAtPoint(qm31Chip *m31.QM31Chip, coeffs []m31.M31, point Point) m31.QM31 {
	n := len(coeffs)
	if n == 0 {
		return qm31Chip.Zero()
	}

	// Handle single coefficient case
	if n == 1 {
		return m31.NewQM31FromM31(coeffs[0])
	}

	// Calculate log size from coefficient length
	logSize := 0
	temp := n
	for temp > 1 {
		logSize++
		temp >>= 1
	}

	// Create folding factors: [point.y, x, double_x(x), ...]
	foldingFactors := createCircleFoldingFactors(qm31Chip, point, logSize)

	// Perform hierarchical fold operation
	return foldM31WithQM31Factors(qm31Chip, coeffs, foldingFactors)
}

// createCircleFoldingFactors creates array of folding factors for circle polynomial evaluation
// Builds the mappings array: [point.y, x, double_x(x), double_x(double_x(x)), ...]
// Then reverses it for proper fold order
func createCircleFoldingFactors(qm31Chip *m31.QM31Chip, point Point, logSize int) []m31.QM31 {
	if logSize == 0 {
		return []m31.QM31{}
	}

	mappings := make([]m31.QM31, logSize)

	// First factor is point.y
	mappings[0] = point.Y

	// Subsequent factors are x, double_x(x), double_x(double_x(x)), ...
	x := point.X
	for i := 1; i < logSize; i++ {
		mappings[i] = x
		// Use doubleX from line_polys.go (or implement here if needed)
		x = doubleX(qm31Chip, x)
	}

	// Reverse the mappings array for proper fold order
	for i := 0; i < logSize/2; i++ {
		mappings[i], mappings[logSize-1-i] = mappings[logSize-1-i], mappings[i]
	}

	return mappings
}

// foldM31WithQM31Factors folds M31 values recursively using QM31 folding factors
// Implementation of the fold function from Rust core::poly::utils::fold
// Coefficients are M31 (BaseField), folding factors are QM31 (SecureField)
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
func foldM31WithQM31Factors(qm31Chip *m31.QM31Chip, values []m31.M31, foldingFactors []m31.QM31) m31.QM31 {
	n := len(values)

	// Base case: single value
	if n == 1 {
		// Convert M31 to QM31 (M31 becomes real part of first CM31)
		return m31.NewQM31FromM31(values[0])
	}

	// Verify that n is a power of two and matches folding factors length
	if n != (1 << len(foldingFactors)) {
		panic("foldM31WithQM31Factors: values length must equal 2^(folding_factors length)")
	}

	// Split values in half
	mid := n / 2
	lhsValues := values[:mid]
	rhsValues := values[mid:]

	// Split folding factors (first factor is used at this level)
	foldingFactor := foldingFactors[0]
	remainingFactors := foldingFactors[1:]

	// Recursively fold left and right halves
	lhsVal := foldM31WithQM31Factors(qm31Chip, lhsValues, remainingFactors)
	rhsVal := foldM31WithQM31Factors(qm31Chip, rhsValues, remainingFactors)

	// Combine: lhs + rhs * folding_factor
	rhsScaled := qm31Chip.Mul(rhsVal, foldingFactor)
	return qm31Chip.Add(lhsVal, rhsScaled)
}

// LogSize returns the maximum log size among all coordinate polynomials
func (p SecureCirclePoly) LogSize() int {
	maxLogSize := logSizeFromLength(len(p.Coeffs0))

	if ls := logSizeFromLength(len(p.Coeffs1)); ls > maxLogSize {
		maxLogSize = ls
	}
	if ls := logSizeFromLength(len(p.Coeffs2)); ls > maxLogSize {
		maxLogSize = ls
	}
	if ls := logSizeFromLength(len(p.Coeffs3)); ls > maxLogSize {
		maxLogSize = ls
	}

	return maxLogSize
}

// logSizeFromLength computes log2 of a power of 2
func logSizeFromLength(n int) int {
	if n == 0 {
		return 0
	}
	logSize := 0
	temp := n
	for temp > 1 {
		logSize++
		temp >>= 1
	}
	return logSize
}
