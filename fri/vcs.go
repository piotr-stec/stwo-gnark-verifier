package fri

import (
	"fmt"
	"math/big"

	"github.com/HerodotusDev/stwo-gnark-verifier/blake2s"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"

	// "github.com/HerodotusDev/stwo-gnark-verifier/utils"
	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/consensys/gnark/std/math/uints"
)

// nextDecommitmentNode fetches the next node that needs to be decommited in the current Merkle layer.
// Returns the minimum of (prev_query/2) and layer_query, or -1 if both iterators are exhausted.
// Advances the iterator pointer(s) for consumed element(s).
func nextDecommitmentNode(
	prevQueries []int, prevIdx *int,
	layerQueries []int, layerIdx *int,
) int {
	var prevVal *int
	var layerVal *int
	
	// Peek at prev_queries (divide by 2 for parent node)
	if *prevIdx < len(prevQueries) {
		val := prevQueries[*prevIdx] / 2
		prevVal = &val
	}
	
	// Peek at layer_queries
	if *layerIdx < len(layerQueries) {
		layerVal = &layerQueries[*layerIdx]
	}
	
	// Return minimum and advance appropriate iterator
	if prevVal != nil && layerVal != nil {
		if *prevVal < *layerVal {
			*prevIdx++
			return *prevVal
		} else if *layerVal < *prevVal {
			*layerIdx++
			return *layerVal
		} else {
			// Equal - advance both
			*prevIdx++
			*layerIdx++
			return *prevVal
		}
	} else if prevVal != nil {
		*prevIdx++
		return *prevVal
	} else if layerVal != nil {
		*layerIdx++
		return *layerVal
	}
	
	return -1 // Both exhausted
}

func getMapKeys(m map[int]logderivlookup.Table) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

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
func NewMerkleVerifier(api frontend.API, uapi *uints.BinaryField[uints.U32], root [32]uints.U8, columnLogSizes []frontend.Variable, nColumnsPerLogSize []int) *MerkleVerifier {
	m31Chip := m31.NewM31Chip(api)
	blake2sChip := blake2s.NewBlake2sChip(api)
	bapi, err := uints.NewBytes(api)
	if err != nil {
		panic(err)
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

func (v *MerkleVerifier) Verify(queries [][]frontend.Variable, queriedValues []m31.M31, decommitment variables.MerkleDecommitment) {
	if len(v.ColumnLogSizes) == 0 {
		return
	}

	fmt.Printf("DEBUG Verify: len(queriedValues)=%d, len(HashWitness)=%d\n", len(queriedValues), len(decommitment.HashWitness))

	maxLogSize := 0
	for _, logSizeVar := range v.ColumnLogSizes {
		if logSizeVar.(int) > maxLogSize {
			maxLogSize = logSizeVar.(int)
		}
	}

	fmt.Printf("N columns per log size: %v\n", v.nColumnsPerLogSize)

	_ = decommitment.HashWitness    // TODO: Use in node processing
	_ = decommitment.ColumnWitness  // TODO: Use in node processing

	// Track queries and hashes from the previous layer as (node_index, hash) pairs
	var lastLayerHashes []struct {
		nodeIndex int
		hash      [32]frontend.Variable
	}
	
	hashWitnessIdx := 0
	queriedValuesIdx := 0
	
	for layerLogSize := maxLogSize; layerLogSize >= 0; layerLogSize-- {
		nColumnsInLayer := v.nColumnsPerLogSize[layerLogSize]
		
		fmt.Printf("Verifying layer log size %d with %d columns\n", layerLogSize, nColumnsInLayer)

		// Get column queries for this layer
		var layerColumnQueries []int
		if layerLogSize < len(queries) && queries[layerLogSize] != nil {
			layerColumnQueries = make([]int, len(queries[layerLogSize]))
			for i, q := range queries[layerLogSize] {
				// q is frontend.Variable containing *big.Int
				qBig := q.(*big.Int)
				layerColumnQueries[i] = int(qBig.Int64())
			}
		}
		
		// Extract prev_layer_queries from lastLayerHashes (node_index from each pair)
		var prevLayerQueries []int
		if lastLayerHashes != nil {
			prevLayerQueries = make([]int, len(lastLayerHashes))
			for i, pair := range lastLayerHashes {
				prevLayerQueries[i] = pair.nodeIndex
			}
		}
		
		// Prepare buffer for queries to current layer (will propagate to next layer)
		var layerTotalQueries []struct {
			nodeIndex int
			hash      [32]frontend.Variable
		}
		
		// Merge previous layer queries and column queries using next_decommitment_node logic
		prevIdx := 0
		layerIdx := 0
		prevHashIdx := 0
		
		for {
			// Remember current layerIdx before calling nextDecommitmentNode
			layerIdxBefore := layerIdx
			
			nodeIndex := nextDecommitmentNode(
				prevLayerQueries, &prevIdx,
				layerColumnQueries, &layerIdx,
			)
			if nodeIndex == -1 {
				break
			}
			
			// Check if node_index came from layer_column_queries
			isInLayerQueries := layerIdx > layerIdxBefore && 
				layerIdxBefore < len(layerColumnQueries) && 
				layerColumnQueries[layerIdxBefore] == nodeIndex
			
			fmt.Printf("Processing node_index=%d, isInLayerQueries=%v\n", nodeIndex, isInLayerQueries)
			
			// Skip duplicate entries in prev_layer_queries for same parent
			for prevIdx < len(prevLayerQueries) && prevLayerQueries[prevIdx]/2 == nodeIndex {
				prevIdx++
			}
			
			// Get node hashes (left and right children) if this is not the largest layer
			var leftHashU8, rightHashU8 [32]uints.U8
			var hasChildren bool
			
			if layerLogSize < maxLogSize {
				hasChildren = true
				
				// Check if left child (2 * node_index) is in prev_layer_hashes
				if prevHashIdx < len(lastLayerHashes) && lastLayerHashes[prevHashIdx].nodeIndex == 2*nodeIndex {
					// Convert from frontend.Variable to uints.U8
					for i := 0; i < 32; i++ {
						leftHashU8[i] = v.bapi.ValueOf(lastLayerHashes[prevHashIdx].hash[i])
					}
					fmt.Printf("  Left child %d found in prev_layer\n", 2*nodeIndex)
					prevHashIdx++
				} else {
					// Read from hash witness
					leftHashU8 = decommitment.HashWitness[hashWitnessIdx]
					fmt.Printf("  Left child %d from witness[%d]\n", 2*nodeIndex, hashWitnessIdx)
					hashWitnessIdx++
				}
				
				// Check if right child (2 * node_index + 1) is in prev_layer_hashes
				if prevHashIdx < len(lastLayerHashes) && lastLayerHashes[prevHashIdx].nodeIndex == 2*nodeIndex+1 {
					// Convert from frontend.Variable to uints.U8
					for i := 0; i < 32; i++ {
						rightHashU8[i] = v.bapi.ValueOf(lastLayerHashes[prevHashIdx].hash[i])
					}
					fmt.Printf("  Right child %d found in prev_layer\n", 2*nodeIndex+1)
					prevHashIdx++
				} else {
					// Read from hash witness
					rightHashU8 = decommitment.HashWitness[hashWitnessIdx]
					fmt.Printf("  Right child %d from witness[%d]\n", 2*nodeIndex+1, hashWitnessIdx)
					hashWitnessIdx++
				}
			}
			
			// Get column values - check if this node_index is in layer_column_queries
			var columnValues []m31.M31
			
			if isInLayerQueries {
				// Read from queried_values
				columnValues = queriedValues[queriedValuesIdx : queriedValuesIdx+nColumnsInLayer]
				queriedValuesIdx += nColumnsInLayer
			} else {
				// Read from column_witness (currently unused in our case)
				// columnValues = decommitment.ColumnWitness[...]
				// For now, leave empty for non-queried nodes
			}
			
			// Compute node hash
			var nodeHash [32]frontend.Variable
			if hasChildren {
				hashU8 := v.blake2sChip.HashNode(leftHashU8[:], rightHashU8[:], columnValues)
				for i := 0; i < 32; i++ {
					nodeHash[i] = hashU8[i].Val
				}
			} else {
				// Largest layer - no children, only column values
				hashU8 := v.blake2sChip.HashNode(nil, nil, columnValues)
				for i := 0; i < 32; i++ {
					nodeHash[i] = hashU8[i].Val
				}
			}
			
			// Store in layer_total_queries
			layerTotalQueries = append(layerTotalQueries, struct {
				nodeIndex int
				hash      [32]frontend.Variable
			}{nodeIndex, nodeHash})
		}
		
		// Store for next iteration
		lastLayerHashes = layerTotalQueries
		fmt.Printf("After layer %d: lastLayerHashes has %d entries\n", layerLogSize, len(lastLayerHashes))
	}
	
	fmt.Printf("Final lastLayerHashes length: %d\n", len(lastLayerHashes))
	
	// Verify root
	if len(lastLayerHashes) != 1 {
		panic(fmt.Sprintf("Expected exactly one root hash, got %d", len(lastLayerHashes)))
	}
	computedRoot := lastLayerHashes[0].hash
	var computedRootU8 [32]uints.U8
	for i := 0; i < 32; i++ {
		computedRootU8[i] = v.bapi.ValueOf(computedRoot[i])
	}
	
	// Debug print roots
	fmt.Printf("Expected root bytes: ")
	for i := 0; i < 32; i++ {
		fmt.Printf("%v ", v.root[i].Val)
	}
	fmt.Printf("\nComputed root bytes: ")
	for i := 0; i < 32; i++ {
		fmt.Printf("%v ", computedRootU8[i].Val)
	}
	fmt.Printf("\n")
	
	for i := 0; i < 32; i++ {
		v.uapi.AssertIsEqual(computedRootU8[i], v.root[i])
	}

}
