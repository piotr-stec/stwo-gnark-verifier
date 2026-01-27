package variables

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/circle"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// ╔══════════════════════════════════╗
// ║         Structure Types          ║
// ╚══════════════════════════════════╝

// StarkProof is the proof emitted by the Stwo Backend
type StarkProof struct {
	Config PcsConfig
	// Commitments are the four commmitment roots. len(Commitments) = 4.
	// Stored as frontend.Variable for witness compatibility
	Commitments [][32]frontend.Variable
	// SampledValues are the sampled values for each column of each tree.
	// len(sampledValues) = 4. len(sampledValues[tree]) = number of columns in the tree.
	// There can be up to 2 values per column (at OODS-1 and OODS for the 4 last interaction columns of a component).
	SampledValues [][][]m31.QM31
	// QueriedValues are the column values queried for the decommitment of the four merkle commitments.
	// len(queriedValues) = 4.
	// len(queriedValues[tree]) = sum for each log size of the number of columns of that log size times the number of deduped queries for that layer.
	QueriedValues [][]m31.M31
	// Decommitments are the decommitments for the four merkle commitments. len(decommitments) = 4.
	Decommitments []MerkleDecommitment
	// FriProof contains the FRI proof data.
	FriProof FriProof
	// ProofOfWork is the FRI proof of work (done by the prover after committing to the FRI layers)
	ProofOfWork uints.U64
	// CompositionPoly is the composition polynomial used to verify constraints
	// This makes the verifier generic and not tied to specific AIR implementations
	CompositionPoly circle.SecureCirclePoly
}

// MerkleDecommitment stores the witness bytes and column values emitted by the prover.
type MerkleDecommitment struct {
	// HashWitness is a stack containing the hash values of nodes required to compute the parent one.
	HashWitness [][32]uints.U8
	// ColumnWitness is unused and could be removed. It is introduced in stwo to have a generic merkle decommitment so that a verifier can
	// ask only for certain column values. However, in practice all columns need to be queried to build the FRI answers.
	ColumnWitness []m31.M31
}

// FriProof stores the FRI proof data
type FriProof struct {
	// FirstLayerProof is the FRI proof for the first layer.
	FirstLayerProof FriLayerProof
	// InnerLayerProofs contains the FRI proofs for the inner layers.
	InnerLayerProofs []FriLayerProof
	// LastLayerPoly is the FRI proof for the last layer which is just a constant polynomial.
	LastLayerPoly circle.LinePoly
}

// FriLayerProof stores the FRI layer proof data
type FriLayerProof struct {
	// Used for layers containing fri answers to get the sibling value of a given query.
	// Typically we might have f(x) but we also need f(-x) for FRI, this accounts for that.
	FriWitness []m31.QM31
	// Decommitment is the decommitment for the FRI layer merkle commitment.
	Decommitment MerkleDecommitment
	// Commitment is the commitment to the FRI layer.
	// Stored as frontend.Variable for witness compatibility
	Commitment [32]frontend.Variable
}

// ╔══════════════════════════════════╗
// ║             Raw Types            ║
// ╚══════════════════════════════════╝

type StarkProofRaw struct {
	Config          PcsConfigRaw            `json:"config"`
	Commitments     [][]uint8               `json:"commitments"`
	SampledValues   SampledValuesRaw        `json:"sampled_values"`
	QueriedValues   [][]uint64              `json:"queried_values"`
	Decommitments   []MerkleDecommitmentRaw `json:"decommitments"`
	FriProof        FriProofRaw             `json:"fri_proof"`
	ProofOfWork     uint64                  `json:"proof_of_work"`
	CompositionPoly *CompositionPolyRaw     `json:"composition_poly"`
}

type PcsConfigRaw struct {
	PowBits   uint8        `json:"pow_bits"`
	FriConfig FriConfigRaw `json:"fri_config"`
}

type FriConfigRaw struct {
	LogBlowupFactor         uint64 `json:"log_blowup_factor"`
	LogLastLayerDegreeBound uint8  `json:"log_last_layer_degree_bound"`
	NQueries                uint8  `json:"n_queries"`
}

type SampledValuesRaw [][][][2][2]uint64

type MerkleDecommitmentRaw struct {
	HashWitness   [][]uint8 `json:"hash_witness"`
	ColumnWitness []uint64  `json:"column_witness"`
}

type FriProofRaw struct {
	FirstLayerProof  FriLayerProofRaw   `json:"first_layer_proof"`
	InnerLayerProofs []FriLayerProofRaw `json:"inner_layer_proofs"`
	LastLayerPoly    LinePolyRaw        `json:"last_layer_poly"`
}

type FriLayerProofRaw struct {
	FriWitness   [][2][2]uint64        `json:"fri_witness"`
	Decommitment MerkleDecommitmentRaw `json:"decommitment"`
	Commitment   []uint8               `json:"commitment"`
}

type LinePolyRaw struct {
	Coeffs  [][2][2]uint64 `json:"coeffs"`
	LogSize uint8          `json:"log_size"`
}

type CompositionPolyRaw struct {
	Coeffs0 []uint64 `json:"coeffs0"`
	Coeffs1 []uint64 `json:"coeffs1"`
	Coeffs2 []uint64 `json:"coeffs2"`
	Coeffs3 []uint64 `json:"coeffs3"`
}

// ╔══════════════════════════════════╗
// ║             Building             ║
// ╚══════════════════════════════════╝

// BuildStarkProof builds a StarkProof from its raw representation.
func BuildStarkProof(starkProofRaw *StarkProofRaw) StarkProof {
	if starkProofRaw == nil {
		return StarkProof{}
	}

	compositionPoly := buildCompositionPoly(starkProofRaw.CompositionPoly)

	return StarkProof{
		Config:          buildPcsConfig(starkProofRaw.Config),
		Commitments:     buildCommitments(starkProofRaw.Commitments),
		SampledValues:   buildSampledValues(starkProofRaw.SampledValues),
		QueriedValues:   buildQueriedValues(starkProofRaw.QueriedValues),
		Decommitments:   buildDecommitments(starkProofRaw.Decommitments),
		FriProof:        buildFriProof(starkProofRaw.FriProof),
		ProofOfWork:     uints.NewU64(starkProofRaw.ProofOfWork),
		CompositionPoly: compositionPoly,
	}
}

func buildPcsConfig(raw PcsConfigRaw) PcsConfig {
	return PcsConfig{
		PowBits: raw.PowBits,
		FriConfig: FriConfig{
			LogBlowupFactor:         int(raw.FriConfig.LogBlowupFactor),
			LogLastLayerDegreeBound: raw.FriConfig.LogLastLayerDegreeBound,
			NQueries:                raw.FriConfig.NQueries,
		},
	}
}

func buildCommitments(raw [][]uint8) [][32]frontend.Variable {
	if len(raw) == 0 {
		return nil
	}

	result := make([][32]frontend.Variable, len(raw))
	for i, entry := range raw {
		if len(entry) != 32 {
			panic("commitment root must be 32 bytes")
		}
		var root [32]frontend.Variable
		for j, b := range entry {
			root[j] = frontend.Variable(b)
		}
		result[i] = root
	}

	return result
}

func buildSampledValues(raw SampledValuesRaw) [][][]m31.QM31 {
	if len(raw) == 0 {
		return nil
	}

	result := make([][][]m31.QM31, len(raw))
	for domainIdx, columns := range raw {
		if len(columns) == 0 {
			continue
		}

		domainValues := make([][]m31.QM31, len(columns))
		for columnIdx, evaluations := range columns {
			if len(evaluations) == 0 {
				continue
			}

			columnValues := make([]m31.QM31, 0, len(evaluations))
			for _, entry := range evaluations {
				// entry is [2][2]uint64
				columnValues = append(columnValues, m31.NewQM31Unchecked(entry[0][0], entry[0][1], entry[1][0], entry[1][1]))
			}
			domainValues[columnIdx] = columnValues
		}
		result[domainIdx] = domainValues
	}

	return result
}

func buildQueriedValues(raw [][]uint64) [][]m31.M31 {
	if len(raw) == 0 {
		return nil
	}

	result := make([][]m31.M31, len(raw))
	for groupIdx, group := range raw {
		if len(group) == 0 {
			continue
		}

		result[groupIdx] = convertUintSliceToM31(group)
	}

	return result
}

func buildDecommitments(raw []MerkleDecommitmentRaw) []MerkleDecommitment {
	if len(raw) == 0 {
		return nil
	}

	result := make([]MerkleDecommitment, len(raw))
	for i, entry := range raw {
		result[i] = MerkleDecommitment{
			HashWitness:   buildHashWitness(entry.HashWitness),
			ColumnWitness: convertUintSliceToM31(entry.ColumnWitness),
		}
	}

	return result
}

func buildHashWitness(raw [][]uint8) [][32]uints.U8 {
	if len(raw) == 0 {
		return nil
	}

	hashes := make([][32]uints.U8, len(raw))
	for i, bytes := range raw {
		var hash [32]uints.U8
		for j := 0; j < len(hash) && j < len(bytes); j++ {
			hash[j] = uints.NewU8(bytes[j])
		}
		hashes[i] = hash
	}

	return hashes
}

func buildFriProof(raw FriProofRaw) FriProof {
	return FriProof{
		FirstLayerProof:  buildFirstLayerProof(raw.FirstLayerProof),
		InnerLayerProofs: buildInnerLayerProofs(raw.InnerLayerProofs),
		LastLayerPoly:    buildLastLayerPoly(raw.LastLayerPoly),
	}
}

func buildFirstLayerProof(raw FriLayerProofRaw) FriLayerProof {
	firstLayerProof := buildInnerLayerProof(raw)
	return firstLayerProof
}

func buildInnerLayerProofs(raw []FriLayerProofRaw) []FriLayerProof {
	result := make([]FriLayerProof, len(raw))
	for i, entry := range raw {
		result[i] = buildInnerLayerProof(entry)
	}
	return result
}

func buildInnerLayerProof(raw FriLayerProofRaw) FriLayerProof {
	friWitness := make([]m31.QM31, len(raw.FriWitness))
	for i, entry := range raw.FriWitness {
		// entry is [2][2]uint64
		friWitness[i] = m31.NewQM31Unchecked(entry[0][0], entry[0][1], entry[1][0], entry[1][1])
	}

	decommitment := buildDecommitments([]MerkleDecommitmentRaw{raw.Decommitment})[0]

	commitment := buildCommitments([][]uint8{raw.Commitment})[0]
	return FriLayerProof{
		FriWitness:   friWitness,
		Decommitment: decommitment,
		Commitment:   commitment,
	}
}

func buildLastLayerPoly(raw LinePolyRaw) circle.LinePoly {
	// Each element in raw.Coeffs is [2][2]uint64 representing one QM31 coefficient
	coeffs := make([]m31.QM31, len(raw.Coeffs))
	for i := 0; i < len(raw.Coeffs); i++ {
		coeffs[i] = m31.NewQM31Unchecked(raw.Coeffs[i][0][0], raw.Coeffs[i][0][1], raw.Coeffs[i][1][0], raw.Coeffs[i][1][1])
	}
	return circle.LinePoly{
		Coeffs:  coeffs,
		LogSize: uints.NewU8(raw.LogSize),
	}
}

func buildCompositionPoly(raw *CompositionPolyRaw) circle.SecureCirclePoly {
	if raw == nil {
		// Return empty polynomial if not provided (for backward compatibility)
		return circle.SecureCirclePoly{
			Coeffs0: []m31.M31{},
			Coeffs1: []m31.M31{},
			Coeffs2: []m31.M31{},
			Coeffs3: []m31.M31{},
		}
	}

	return circle.NewSecureCirclePoly(
		convertUintSliceToM31(raw.Coeffs0),
		convertUintSliceToM31(raw.Coeffs1),
		convertUintSliceToM31(raw.Coeffs2),
		convertUintSliceToM31(raw.Coeffs3),
	)
}
