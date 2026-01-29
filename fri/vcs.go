package fri

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/blake2s"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/HerodotusDev/stwo-gnark-verifier/utils"
	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/consensys/gnark/std/math/uints"
)

// MerkleVerifier is a circuit gadget for verifying a Merkle decommitment
type MerkleVerifier struct {
	api         frontend.API
	uapi        *uints.BinaryField[uints.U32]
	bapi        *uints.Bytes
	m31Chip     *m31.M31Chip
	blake2sChip *blake2s.Blake2sChip

	root               [32]uints.U8
	ColumnLogSizes     []frontend.Variable
	nColumnsPerLogSize []int
	maxLogSize         int
}

// NewMerkleVerifier initializes a new MerkleVerifier
func NewMerkleVerifier(api frontend.API, uapi *uints.BinaryField[uints.U32], rootVar [32]frontend.Variable, columnLogSizes []frontend.Variable, nColumnsPerLogSize []int) *MerkleVerifier {
	m31Chip := m31.NewM31Chip(api)
	blake2sChip := blake2s.NewBlake2sChip(api)
	bapi, err := uints.NewBytes(api)
	if err != nil {
		panic(err)
	}

	// Convert root from frontend.Variable to uints.U8
	var root [32]uints.U8
	for i := 0; i < 32; i++ {
		root[i] = bapi.ValueOf(rootVar[i])
	}

	maxLogSize := 0
	for i, nColumns := range nColumnsPerLogSize {
		if nColumns > 0 {
			maxLogSize = i
		}
	}

	return &MerkleVerifier{
		api:                api,
		uapi:               uapi,
		bapi:               bapi,
		m31Chip:            m31Chip,
		blake2sChip:        blake2sChip,
		root:               root,
		ColumnLogSizes:     columnLogSizes,
		nColumnsPerLogSize: nColumnsPerLogSize,
		maxLogSize:         maxLogSize,
	}
}

// Verify verifies the Merkle decommitment for the given queries and queried values
// This version uses hints to determine branching but enforces correctness in circuit.
func (v *MerkleVerifier) Verify(queries [][]frontend.Variable, queriedValues []m31.M31, decommitment variables.MerkleDecommitment) {
	// Pre-compute zero hash for dummies
	zeroHash := [32]uints.U8{}
	for i := range zeroHash {
		zeroHash[i] = uints.NewU8(0)
	}

	// Prepare witness lookup table
	witnessTable := logderivlookup.New(v.api)
	for _, w := range decommitment.HashWitness {
		lo, hi := utils.SplitHash(v.api, w)
		witnessTable.Insert(lo)
		witnessTable.Insert(hi)
	}
	// Add dummy witness (zeros) just in case
	witnessTable.Insert(frontend.Variable(0))
	witnessTable.Insert(frontend.Variable(0))

	witnessIdx := frontend.Variable(0)

	remainingValues := queriedValues

	// layerHashes stores the computed hashes (lo, hi) for each query at each layer.
	layerHashes := make([]logderivlookup.Table, v.maxLogSize+1)

	// Decommit layer by layer from leaves (maxLogSize) to root (0)
	for layerLog := v.maxLogSize; ; layerLog-- {
		layerHashes[layerLog] = logderivlookup.New(v.api)

		nColumnsInLayer := 0
		if layerLog < len(v.nColumnsPerLogSize) {
			nColumnsInLayer = v.nColumnsPerLogSize[layerLog]
		}

		// Skip layers with no queries (nil entries in queries array)
		if layerLog >= len(queries) || queries[layerLog] == nil {
			if layerLog == 0 {
				break
			}
			continue
		}

		queriesInLayer := queries[layerLog]
		nQueries := len(queriesInLayer)

		// If not at the bottom, we need branching info and next layer query table
		var branching []frontend.Variable
		var queriesNextTable logderivlookup.Table
		if layerLog < v.maxLogSize {
			queriesNextLayer := queries[layerLog+1]
			// Call hint to get branching
			inputs := append(queriesInLayer, queriesNextLayer...)
			var err error
			branching, err = v.api.Compiler().NewHint(utils.QueriesBranchingHint, nQueries, inputs...)
			if err != nil {
				panic(err)
			}

			queriesNextTable = logderivlookup.New(v.api)
			for _, q := range queriesNextLayer {
				queriesNextTable.Insert(q)
			}
			queriesNextTable.Insert(frontend.Variable(1 << 32)) // dummy
			queriesNextTable.Insert(frontend.Variable(1 << 32)) // dummy
		}

		// Pointer to consume queries from next layer (children)
		childIdx := frontend.Variable(0)

		// Iterate over all queries in this layer
		for i, query := range queriesInLayer {
			isDummy := v.api.IsZero(v.api.Sub(query, frontend.Variable(1<<32)))

			// 1. Get column values
			var columnValues []m31.M31
			if nColumnsInLayer > 0 {
				columnValues = make([]m31.M31, nColumnsInLayer)
				if len(remainingValues) >= nColumnsInLayer {
					columnValues = remainingValues[:nColumnsInLayer]
					remainingValues = remainingValues[nColumnsInLayer:]
				} else {
					for k := 0; k < nColumnsInLayer; k++ {
						columnValues[k] = m31.Zero()
					}
				}
			}

			// 2. Compute hash
			var hash [32]uints.U8

			if layerLog == v.maxLogSize {
				// Leaf: hash column values
				hash = v.blake2sChip.HashNode(nil, nil, columnValues)
				hash = utils.SelectHash(v.api, isDummy, zeroHash, hash)
			} else {
				// Internal node
				branchCode := branching[i]

				bits := v.api.ToBinary(branchCode, 2)
				leftPresent := bits[0]
				rightPresent := bits[1]

				// Force branching to 0 if dummy
				leftPresent = v.api.Select(isDummy, 0, leftPresent)
				rightPresent = v.api.Select(isDummy, 0, rightPresent)

				parentQueryBinary := v.api.ToBinary(query, 32)
				leftChild := v.api.FromBinary(append([]frontend.Variable{0}, parentQueryBinary...)...)
				rightChild := v.api.Add(leftChild, 1)

				// Verify left child
				qLeft := queriesNextTable.Lookup(childIdx)[0]
				v.api.AssertIsEqual(v.api.Select(leftPresent, qLeft, leftChild), leftChild)

				// Verify right child
				idxRight := v.api.Add(childIdx, leftPresent)
				qRight := queriesNextTable.Lookup(idxRight)[0]
				v.api.AssertIsEqual(v.api.Select(rightPresent, qRight, rightChild), rightChild)

				// Get children hashes
				twoChildIdx := v.api.Mul(childIdx, 2)
				hLeftLo := layerHashes[layerLog+1].Lookup(twoChildIdx)[0]
				hLeftHi := layerHashes[layerLog+1].Lookup(v.api.Add(twoChildIdx, 1))[0]
				hLeftCalc := utils.RebuildHash(v.api, hLeftLo, hLeftHi)

				twoIdxRight := v.api.Mul(idxRight, 2)
				hRightLo := layerHashes[layerLog+1].Lookup(twoIdxRight)[0]
				hRightHi := layerHashes[layerLog+1].Lookup(v.api.Add(twoIdxRight, 1))[0]
				hRightCalc := utils.RebuildHash(v.api, hRightLo, hRightHi)

				// Get witness hashes
				twoWitnessIdx := v.api.Mul(witnessIdx, 2)
				w0Lo := witnessTable.Lookup(twoWitnessIdx)[0]
				w0Hi := witnessTable.Lookup(v.api.Add(twoWitnessIdx, 1))[0]
				w0 := utils.RebuildHash(v.api, w0Lo, w0Hi)

				// If we need a second witness (neither child present), it's at witnessIdx + 1
				// But here we need witnesses for missing children.
				// If left missing, we take w0.
				// If right missing, we take w0 (if left present) or w1 (if left missing).

				// Logic:
				// leftHash = leftPresent ? hLeftCalc : w0
				// If !leftPresent, we consumed w0. Next witness is w0+1 (which is w1 relative to start).
				// rightHash = rightPresent ? hRightCalc : (leftPresent ? w0 : w1)

				leftHash := utils.SelectHash(v.api, leftPresent, hLeftCalc, w0)

				witnessOffset := v.api.Sub(1, leftPresent) // 1 if left missing, 0 if present
				idxWRight := v.api.Add(witnessIdx, witnessOffset)
				twoIdxWRight := v.api.Mul(idxWRight, 2)
				wRightLo := witnessTable.Lookup(twoIdxWRight)[0]
				wRightHi := witnessTable.Lookup(v.api.Add(twoIdxWRight, 1))[0]
				wRight := utils.RebuildHash(v.api, wRightLo, wRightHi)

				rightHash := utils.SelectHash(v.api, rightPresent, hRightCalc, wRight)

				// Update indices
				childIdx = v.api.Add(childIdx, v.api.Add(leftPresent, rightPresent))

				witnessConsumed := v.api.Add(v.api.Sub(1, leftPresent), v.api.Sub(1, rightPresent))
				witnessIdx = v.api.Add(witnessIdx, witnessConsumed)

				// Compute node hash
				nodeHash := v.blake2sChip.HashNode(leftHash[:], rightHash[:], columnValues)
				hash = utils.SelectHash(v.api, isDummy, zeroHash, nodeHash)
			}

			lo, hi := utils.SplitHash(v.api, hash)
			layerHashes[layerLog].Insert(lo)
			layerHashes[layerLog].Insert(hi)
		}

		// Add dummies to table to support dummy lookups
		layerHashes[layerLog].Insert(frontend.Variable(0))
		layerHashes[layerLog].Insert(frontend.Variable(0))
		layerHashes[layerLog].Insert(frontend.Variable(0))
		layerHashes[layerLog].Insert(frontend.Variable(0))

		if layerLog == 0 {
			break
		}
	}

	// assert root match for valid queries
	// Queries at layer 0 are roots.
	// Usually there's only 1 root (index 0).
	// Dummies are at index 1+.
	// We check all queries.
	rootHash := v.root
	for i := 0; i < len(queries[0]); i++ {
		isDummy := v.api.IsZero(v.api.Sub(queries[0][i], frontend.Variable(1<<32)))

		hLo := layerHashes[0].Lookup(frontend.Variable(2 * i))[0]
		hHi := layerHashes[0].Lookup(frontend.Variable(2*i + 1))[0]
		h := utils.RebuildHash(v.api, hLo, hHi)

		expected := utils.SelectHash(v.api, isDummy, zeroHash, rootHash)
		for j := 0; j < 32; j++ {
			v.uapi.AssertIsEqual(h[j], expected[j])
		}
	}
}
