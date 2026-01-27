# Generic AIR Verification - Quick Start

## Nowy Interfejs Weryfikacji

### Stary sposób (Cairo-specific, DEPRECATED):

```go
verifier.VerifyLegacy(
    proof,
    pcsConfig,
    circuitData,
    commitmentVerifier,
    compositionLogDegreeBound,
    compositionPolynomial,
)
```

### Nowy sposób (Generic AIR):

```go
verifier.Verify(proof, params)
```

## Przygotowanie Proof

Composition polynomial musi być częścią proof:

```json
{
  "stark_proof": {
    "config": {...},
    "commitments": [...],
    "sampled_values": [...],
    "queried_values": [...],
    "decommitments": [...],
    "fri_proof": {...},
    "proof_of_work": 12345,
    "composition_poly": {
      "coeffs0": [1, 2, 3, ...],
      "coeffs1": [4, 5, 6, ...],
      "coeffs2": [7, 8, 9, ...],
      "coeffs3": [10, 11, 12, ...]
    }
  }
}
```

## Przygotowanie VerificationParams

```go
params := variables.VerificationParams{
    // Komponenty (dla Cairo: opcodes, builtins, memory, etc.)
    ComponentParams: []variables.ComponentParams{
        {
            LogSize: 10,
            ClaimedSum: qm31Value,
            Info: variables.ComponentInfo{
                MaxConstraintLogDegreeBound: 12,
                LogSize: 10,
                MaskOffsets: maskOffsets,
                PreprocessedColumns: []frontend.Variable{0, 1, 2},
            },
        },
        // ... więcej komponentów
    },
    
    // Globalne parametry
    NPreprocessedColumns: 100,
    ComponentsCompositionLogDegreeBound: 15,
    
    // Commitment trees info
    TreeRoots: [][32]frontend.Variable{
        root1, root2, root3, root4,
    },
    TreeColumnLogSizes: [][]frontend.Variable{
        {10, 11, 12},  // tree 0
        {10, 11},      // tree 1
        {12},          // tree 2
        {15, 15, 15, 15},  // tree 3 (composition)
    },
    
    // Channel initialization
    Digest: digestBytes,  // [32]frontend.Variable
    NDraws: 0,
}
```

## Generowanie Digest

Digest to hash stanu weryfikacji (np. konfiguracji proof, public inputs, etc.):

```go
// Przykład: hash konfiguracji + public data
digest := blake2s.Hash(
    proofConfig.Encode(),
    publicInputs.Encode(),
)
```

## Przykład Użycia

```go
// 1. Wczytaj proof z JSON
proofRaw := variables.ReadCairoProof("proof.json")
proof := variables.BuildProof(proofRaw)

// 2. Przygotuj parametry weryfikacji
params := prepareVerificationParams(proof, config)

// 3. Utwórz verifier chip
verifierChip := verifier.NewVerifierChip(api)

// 4. Zweryfikuj!
verifierChip.Verify(proof.StarkProof, params)
```

## Migracja z Starego API

Jeśli masz istniejący kod używający `VerifyLegacy`, możesz:

1. **Opcja A - Tymczasowo:** Kontynuuj używanie `VerifyLegacy` (działa, ale deprecated)

2. **Opcja B - Migracja:** Przekształć parametry na `VerificationParams`:

```go
// Stary kod:
verifier.VerifyLegacy(proof, pcsConfig, circuitData, commitmentVerifier, bound, poly)

// Nowy kod:
params := variables.VerificationParams{
    ComponentParams: extractFromCircuitData(circuitData),
    TreeRoots: commitmentVerifier.Roots,
    TreeColumnLogSizes: commitmentVerifier.ColumnLogSizes,
    ComponentsCompositionLogDegreeBound: bound,
    Digest: calculateDigest(proof),
    NDraws: 0,
    // ...
}
verifier.Verify(proof, params)
```

## Zalety Nowego API

✅ **Prostsze:** 2 parametry zamiast 6  
✅ **Generyczne:** Nie wymaga specyfiki Cairo  
✅ **Zgodne z Solidity:** Ta sama architektura  
✅ **Extensible:** Łatwo dodawać nowe AIRs  

## Uwagi

⚠️ **Work in Progress:** Implementacja jest niekompletna. Zobacz `REFACTORING_NOTES.md` dla TODO list.

⚠️ **CircuitData:** Wciąż używane wewnętrznie - będzie usunięte w przyszłości.

⚠️ **Komponenty Cairo:** Hardkodowane `components.NewComponents()` - będzie zastąpione generyczną wersją.
