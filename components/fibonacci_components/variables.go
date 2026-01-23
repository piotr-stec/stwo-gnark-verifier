package fibonacci_components

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

const (
	// Tree indices for Fibonacci proof structure
	PREPROCESSED_IDX = 0 // Empty for Fibonacci (no preprocessed columns)
	TRACE_IDX        = 1 // Trace containing Fibonacci sequence
	CP_IDX           = 2 // Composition polynomial
	N_TREES          = 3 // Total number of trees
)

// Traces encapsulates the sampled values for the Fibonacci trace
type Traces struct {
	trace [][]m31.QM31
}

// NewTraces builds a Traces helper from the sampled values.
func NewTraces(trace [][]m31.QM31) *Traces {
	return &Traces{
		trace: trace,
	}
}

// RemainingTrace returns the number of trace samples left to consume.
func (t *Traces) RemainingTrace() int {
	return len(t.trace)
}

// Take returns the next trace samples and advances the internal cursor.
// For Fibonacci, we need to return samples at multiple mask points.
func (t *Traces) Take(numSamples int) []m31.QM31 {
	if numSamples < 0 {
		panic("trace consumption count must be non-negative")
	}
	if len(t.trace) == 0 {
		panic("no trace data available")
	}

	// For Fibonacci, we have one trace column
	// Return the first 'numSamples' values from the trace
	traceColumn := t.trace[0]
	if len(traceColumn) < numSamples {
		panic("insufficient trace samples for Fibonacci evaluation")
	}

	samples := make([]m31.QM31, numSamples)
	copy(samples, traceColumn[:numSamples])

	return samples
}
