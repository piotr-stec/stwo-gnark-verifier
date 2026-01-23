package fibonacci_components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
)

const (
	// FibonacciTraceColumns represents the number of trace columns for Fibonacci
	// We need 3 consecutive mask points: f(n-2), f(n-1), f(n)
	FibonacciTraceColumns = 1

	// FibonacciInteractionColumns - Fibonacci doesn't use interactions
	FibonacciInteractionColumns = 0
)

// FibonacciClaim holds the claim for the Fibonacci component
type FibonacciClaim struct {
	LogSize frontend.Variable
}

// FibonacciComponent implements the Fibonacci constraint: f(n) = f(n-1) + f(n-2)
type FibonacciComponent struct {
	api  frontend.API
	m31  *m31.M31Chip
	qm31 *m31.QM31Chip

	logSize       frontend.Variable
	columnSize    m31.QM31
	columnSizeInv m31.QM31
	vanishEvalInv m31.QM31
}

// NewFibonacciComponent creates a new Fibonacci component
func NewFibonacciComponent(
	api frontend.API,
	m31Chip *m31.M31Chip,
	qm31Chip *m31.QM31Chip,
	vanishEvalInv m31.QM31,
	claim FibonacciClaim,
) FibonacciComponent {
	columnSize := computeColumnSize(api, claim.LogSize)
	columnSizeInv := qm31Chip.Inverse(columnSize)

	return FibonacciComponent{
		api:           api,
		m31:           m31Chip,
		qm31:          qm31Chip,
		logSize:       claim.LogSize,
		columnSize:    columnSize,
		columnSizeInv: columnSizeInv,
		vanishEvalInv: vanishEvalInv,
	}
}

// Evaluate implements the Fibonacci constraint evaluation
// Constraint: f(n) = f(n-1) + f(n-2)
// In the trace, we have one column with values: [f(0), f(1), f(2), ..., f(n)]
// We check that for each row: current = prev + prev_prev
func (c FibonacciComponent) Evaluate(traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	traceSampledValues := traces.Take(FibonacciTraceColumns)

	// Get the trace column (single column containing Fibonacci sequence)
	// The trace is evaluated at the OODS point and contains samples at different offsets
	// We need 3 consecutive samples to verify the constraint

	// In the mask, we have samples at offsets corresponding to:
	// - offset 0: f(n-2)
	// - offset 1: f(n-1)
	// - offset 2: f(n)

	// Note: The actual mask point sampling is handled by the trace system
	// Here we receive the sampled values and need to evaluate the constraint

	// For Fibonacci, the trace column contains all values
	// At OODS evaluation, we get samples for consecutive points
	if len(traceSampledValues) < 3 {
		panic("insufficient trace samples for Fibonacci constraint")
	}

	// Read three consecutive mask values
	fN2 := traceSampledValues[0] // f(n-2)
	fN1 := traceSampledValues[1] // f(n-1)
	fN := traceSampledValues[2]  // f(n)

	// Compute the constraint: f(n) - (f(n-1) + f(n-2))
	// This should equal zero if the constraint is satisfied
	sum := c.qm31.Add(fN1, fN2)
	constraint := c.qm31.Sub(fN, sum)

	// Accumulate the constraint
	// The constraint is weighted by randomCoeff and accumulated
	return c.qm31.Mul(constraint, randomCoeff)
}
