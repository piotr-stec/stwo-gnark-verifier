# Generic Verification Testing Guide

## Overview
This guide explains how to test the generic Stwo verification with separate JSON files for proof and verification parameters.

## Test Structure

### Files Created
1. **`variables/verification_params_raw.go`** - JSON deserializ ation and building functions
2. **`verifier/verify_generic_test.go`** - Test functions
3. **`test_data/verification_params_example.json`** - Example verification parameters

## JSON Format

### VerificationParams JSON
```json
{
  "component_params": [
    {
      "log_size": 10,
      "claimed_sum": [0, 0, 0, 0],  // QM31 as 4 M31 values
      "info": {
        "max_constraint_log_degree_bound": 12,
        "log_size": 10,
        "mask_offsets": [              // [tree][column][offset_values]
          [[0]],                       // tree 0, column 0, offset 0
          [[0, 1]]                     // tree 1, column 0, offsets 0,1
        ],
        "preprocessed_columns": []
      }
    }
  ],
  "n_preprocessed_columns": 0,
  "components_composition_log_degree_bound": 15,
  "tree_roots": [
    [1,2,3,...,32],                   // 32 bytes per root
    [33,34,35,...,64]
  ],
  "tree_column_log_sizes": [
    [10, 10],                         // tree 0 has 2 columns, both log size 10
    [11]                              // tree 1 has 1 column, log size 11
  ],
  "digest": [1234567890, 987654321, 1111111111, 2222222222, 3333333333, 444444444, 555555555, 666666666],  // 8 x uint32
  "n_draws": 10
}
```

### StarkProof JSON
The StarkProof should be loaded from existing Cairo proof format (see `test_data/all_components_one_query.json` for reference).

## Available Tests

### 1. TestLoadVerificationParams
Tests loading and parsing JSON verification parameters.

```bash
go test -v ./verifier -run TestLoad
```

**Validates:**
- JSON parsing
- Component params loading
- Tree roots and column log sizes
- Digest format

### 2. TestBuildVerificationParams
Tests conversion from raw JSON to circuit-ready structures.

```bash
go test -v ./verifier -run TestBuild
```

**Validates:**
- frontend.Variable conversion
- uints.U8/U32 conversion
- m31.QM31 construction
- Structure completeness

### 3. TestVerifyGeneric (Template)
Template for full verification test (currently skipped).

```bash
go test -v ./verifier -run TestVerifyGeneric
```

**To use:**
1. Create valid `stark_proof_example.json`
2. Create corresponding `verification_params_example.json`
3. Remove `t.Skip()` line
4. Implement circuit compilation if needed

## API Functions

### Loading from JSON
```go
// Load verification params
paramsRaw, err := variables.ReadVerificationParams("path/to/params.json")
if err != nil {
    return err
}

// Convert to circuit-ready format
params := variables.BuildVerificationParams(paramsRaw)
```

### Using in Verification
```go
// In circuit context
verifierChip := NewVerifierChip(api)
verifierChip.Verify(starkProof, verificationParams)
```

## Key Conversions

| Raw JSON Type | Circuit Type | Conversion |
|--------------|-------------|------------|
| `uint64` | `frontend.Variable` | Direct cast |
| `[]uint8` (32 bytes) | `[32]uints.U8` | `uints.NewU8()` |
| `[]uint32` (8 words) | `[8]uints.U32` | `uints.NewU32()` |
| `[4]uint64` | `m31.QM31` | `QM31FromRaw()` |
| `int32` (mask offset) | `frontend.Variable` | Cast to `uint32` |

## Mask Offsets Format

Mask offsets are stored as signed int32 values in JSON and converted to unsigned representation in circuits:
- Positive offsets: direct conversion
- Negative offsets: two's complement (e.g., -1 → 0xFFFFFFFF → 4294967295)

## Tree Structure

The verification params support multiple trees, each with multiple columns:
- **Tree 0**: Usually preprocessed/trace columns
- **Tree 1**: Main trace columns
- **Tree 2**: Interaction columns
- **Tree 3**: Composition polynomial

Each tree has:
- **Root**: 32-byte Merkle root
- **Column log sizes**: Array of log₂(column_size) for each column

## Example: Creating Your Own Test

```go
func TestMyVerification(t *testing.T) {
    // Load params
    paramsRaw, err := variables.ReadVerificationParams("my_params.json")
    require.NoError(t, err)
    
    // Load proof
    proofRaw, err := variables.ReadCairoProof("my_proof.json")
    require.NoError(t, err)
    
    // Build structures
    params := variables.BuildVerificationParams(paramsRaw)
    proof := variables.BuildProof(*proofRaw)
    
    // In circuit context:
    // verifierChip := NewVerifierChip(api)
    // verifierChip.Verify(proof.StarkProof, params)
}
```

## Running All Tests

```bash
# Run all verifier tests
go test -v ./verifier

# Run only generic verification tests
go test -v ./verifier -run TestLoad
go test -v ./verifier -run TestBuild

# Run with coverage
go test -v -cover ./verifier
```

## Notes

1. **Digest Values**: Must be valid uint32 (max 4,294,967,295)
2. **Tree Roots**: Must be exactly 32 bytes each
3. **Component Count**: Can be any number, not limited to Cairo components
4. **Mask Offsets**: Support both positive and negative offsets as signed int32
5. **Circuit Compilation**: Full verification test requires gnark circuit compilation

## Future Improvements

- [ ] Add StarkProof JSON loader for generic format
- [ ] Create test fixtures with valid proof+params pairs
- [ ] Add circuit compilation test
- [ ] Support witness generation from JSON
- [ ] Add validation for params consistency
