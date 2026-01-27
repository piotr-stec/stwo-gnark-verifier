package variables

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
)

// VerificationParamsRaw is the JSON-deserializable version of VerificationParams
type VerificationParamsRaw struct {
	ComponentParams                     []ComponentParamsRaw `json:"component_params"`
	NPreprocessedColumns                uint64               `json:"n_preprocessed_columns"`
	ComponentsCompositionLogDegreeBound uint64               `json:"components_composition_log_degree_bound"`
	TreeRoots                           [][]uint8            `json:"tree_roots"`            // [][32]bytes
	TreeColumnLogSizes                  [][]uint64           `json:"tree_column_log_sizes"` // [tree][column]
	Digest                              []uint32             `json:"digest"`                // [8]u32
	NDraws                              uint64               `json:"n_draws"`
}

// ComponentParamsRaw is the JSON-deserializable version of ComponentParams
type ComponentParamsRaw struct {
	LogSize     uint64           `json:"log_size,omitempty"`
	LogSize2    uint64           `json:"LogSize,omitempty"`     // Support both formats
	ClaimedSum  interface{}      `json:"claimed_sum,omitempty"` // Can be [4]uint64 or [[2]uint64, [2]uint64]
	ClaimedSum2 interface{}      `json:"ClaimedSum,omitempty"`  // Support both formats
	Info        ComponentInfoRaw `json:"info,omitempty"`
	Info2       ComponentInfoRaw `json:"Info,omitempty"` // Support both formats
}

// ComponentInfoRaw is the JSON-deserializable version of ComponentInfo
type ComponentInfoRaw struct {
	MaxConstraintLogDegreeBound  uint64      `json:"max_constraint_log_degree_bound,omitempty"`
	MaxConstraintLogDegreeBound2 uint64      `json:"MaxConstraintLogDegreeBound,omitempty"` // Support both formats
	LogSize                      uint64      `json:"log_size,omitempty"`
	LogSize2                     uint64      `json:"LogSize,omitempty"`      // Support both formats
	MaskOffsets                  [][][]int32 `json:"mask_offsets,omitempty"` // [tree][column][offset_values]
	MaskOffsets2                 [][][]int32 `json:"MaskOffsets,omitempty"`  // Support both formats
	PreprocessedColumns          []uint64    `json:"preprocessed_columns,omitempty"`
	PreprocessedColumns2         []uint64    `json:"PreprocessedColumns,omitempty"` // Support both formats
}

// ReadVerificationParams loads verification parameters from a JSON file
func ReadVerificationParams(path string) (*VerificationParamsRaw, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = file.Close()
	}()

	return readVerificationParamsFromReader(file)
}

// readVerificationParamsFromReader decodes verification params from a reader
func readVerificationParamsFromReader(r io.Reader) (*VerificationParamsRaw, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var params VerificationParamsRaw
	if err := json.Unmarshal(data, &params); err != nil {
		return nil, err
	}

	return &params, nil
}

// BuildVerificationParams converts VerificationParamsRaw to circuit-ready VerificationParams
func BuildVerificationParams(raw *VerificationParamsRaw) VerificationParams {
	// Build component params
	componentParams := make([]ComponentParams, len(raw.ComponentParams))
	for i, cpRaw := range raw.ComponentParams {
		// Extract LogSize (support both formats)
		logSize := cpRaw.LogSize
		if logSize == 0 {
			logSize = cpRaw.LogSize2
		}

		// Extract and convert ClaimedSum
		claimedSum := extractClaimedSum(cpRaw)

		// Extract Info (support both formats)
		info := cpRaw.Info
		if info.MaxConstraintLogDegreeBound == 0 && info.LogSize == 0 {
			info = cpRaw.Info2
		}

		componentParams[i] = ComponentParams{
			LogSize:    int(logSize),
			ClaimedSum: claimedSum,
			Info: ComponentInfo{
				MaxConstraintLogDegreeBound: getMaxConstraintLogDegreeBound(info),
				LogSize:                     getInfoLogSize(info),
				MaskOffsets:                 convertMaskOffsets(getMaskOffsets(info)),
				PreprocessedColumns:         convertToInts(getPreprocessedColumns(info)),
			},
		}
	}

	// Build tree roots - store as frontend.Variable (bytes) for witness compatibility
	treeRoots := make([][32]frontend.Variable, len(raw.TreeRoots))
	for i, root := range raw.TreeRoots {
		for j := 0; j < 32 && j < len(root); j++ {
			treeRoots[i][j] = frontend.Variable(root[j])
		}
	}

	// DEBUG: Print first tree root
	if len(treeRoots) > 0 {
		fmt.Printf("DEBUG BuildVerificationParams: treeRoots[0][0] = %v (type %T)\n", treeRoots[0][0], treeRoots[0][0])
	}

	// Build tree column log sizes
	treeColumnLogSizes := make([][]int, len(raw.TreeColumnLogSizes))
	for i, treeSizes := range raw.TreeColumnLogSizes {
		treeColumnLogSizes[i] = make([]int, len(treeSizes))
		for j, size := range treeSizes {
			treeColumnLogSizes[i][j] = int(size)
		}
	}

	// Build digest - store as frontend.Variable for witness compatibility
	var digest [8]frontend.Variable
	for i := 0; i < 8 && i < len(raw.Digest); i++ {
		digest[i] = frontend.Variable(raw.Digest[i])
	}

	// DEBUG: Print loaded digest
	fmt.Printf("DEBUG BuildVerificationParams: raw.Digest = %v\n", raw.Digest)
	fmt.Printf("DEBUG BuildVerificationParams: digest[0] = %v\n", digest[0])

	return VerificationParams{
		ComponentParams:                     componentParams,
		NPreprocessedColumns:                int(raw.NPreprocessedColumns),
		ComponentsCompositionLogDegreeBound: int(raw.ComponentsCompositionLogDegreeBound),
		TreeRoots:                           treeRoots,
		TreeColumnLogSizes:                  treeColumnLogSizes,
		Digest:                              digest,
		NDraws:                              frontend.Variable(raw.NDraws),
	}
}

// Helper functions
func convertMaskOffsets(raw [][][]int32) [][][]int {
	result := make([][][]int, len(raw))
	for i, tree := range raw {
		result[i] = make([][]int, len(tree))
		for j, col := range tree {
			result[i][j] = make([]int, len(col))
			for k, offset := range col {
				result[i][j][k] = int(offset)
			}
		}
	}
	return result
}

func convertToInts(raw []uint64) []int {
	result := make([]int, len(raw))
	for i, val := range raw {
		result[i] = int(val)
	}
	return result
}

// extractClaimedSum handles both 1D [a,b,c,d] and 2D [[a,b],[c,d]] formats
func extractClaimedSum(cpRaw ComponentParamsRaw) m31.QM31 {
	// First try direct array format from ClaimedSum field
	if cpRaw.ClaimedSum != nil {
		switch v := cpRaw.ClaimedSum.(type) {
		case []interface{}:
			if len(v) == 4 {
				// 1D format: [a,b,c,d]
				nums := make([]uint64, 4)
				for i := 0; i < 4; i++ {
					if num, ok := v[i].(float64); ok {
						nums[i] = uint64(num)
					}
				}
				return QM31FromRaw([4]uint64{nums[0], nums[1], nums[2], nums[3]})
			} else if len(v) == 2 {
				// 2D format: [[a,b],[c,d]]
				if arr1, ok := v[0].([]interface{}); ok && len(arr1) == 2 {
					if arr2, ok := v[1].([]interface{}); ok && len(arr2) == 2 {
						nums := make([]uint64, 4)
						if n0, ok := arr1[0].(float64); ok {
							nums[0] = uint64(n0)
						}
						if n1, ok := arr1[1].(float64); ok {
							nums[1] = uint64(n1)
						}
						if n2, ok := arr2[0].(float64); ok {
							nums[2] = uint64(n2)
						}
						if n3, ok := arr2[1].(float64); ok {
							nums[3] = uint64(n3)
						}
						return QM31FromRaw([4]uint64{nums[0], nums[1], nums[2], nums[3]})
					}
				}
			}
		}
	}

	// Try alternative field ClaimedSum2
	if cpRaw.ClaimedSum2 != nil {
		switch v := cpRaw.ClaimedSum2.(type) {
		case []interface{}:
			if len(v) == 4 {
				nums := make([]uint64, 4)
				for i := 0; i < 4; i++ {
					if num, ok := v[i].(float64); ok {
						nums[i] = uint64(num)
					}
				}
				return QM31FromRaw([4]uint64{nums[0], nums[1], nums[2], nums[3]})
			} else if len(v) == 2 {
				if arr1, ok := v[0].([]interface{}); ok && len(arr1) == 2 {
					if arr2, ok := v[1].([]interface{}); ok && len(arr2) == 2 {
						nums := make([]uint64, 4)
						if n0, ok := arr1[0].(float64); ok {
							nums[0] = uint64(n0)
						}
						if n1, ok := arr1[1].(float64); ok {
							nums[1] = uint64(n1)
						}
						if n2, ok := arr2[0].(float64); ok {
							nums[2] = uint64(n2)
						}
						if n3, ok := arr2[1].(float64); ok {
							nums[3] = uint64(n3)
						}
						return QM31FromRaw([4]uint64{nums[0], nums[1], nums[2], nums[3]})
					}
				}
			}
		}
	}

	// Default to zero
	return QM31FromRaw([4]uint64{0, 0, 0, 0})
}

// Helper functions to extract fields supporting both formats
func getMaxConstraintLogDegreeBound(info ComponentInfoRaw) int {
	if info.MaxConstraintLogDegreeBound != 0 {
		return int(info.MaxConstraintLogDegreeBound)
	}
	return int(info.MaxConstraintLogDegreeBound2)
}

func getInfoLogSize(info ComponentInfoRaw) int {
	if info.LogSize != 0 {
		return int(info.LogSize)
	}
	return int(info.LogSize2)
}

func getMaskOffsets(info ComponentInfoRaw) [][][]int32 {
	if len(info.MaskOffsets) > 0 {
		return info.MaskOffsets
	}
	return info.MaskOffsets2
}

func getPreprocessedColumns(info ComponentInfoRaw) []uint64 {
	if len(info.PreprocessedColumns) > 0 {
		return info.PreprocessedColumns
	}
	return info.PreprocessedColumns2
}

// QM31FromRaw converts raw M31 values to m31.QM31
func QM31FromRaw(raw [4]uint64) m31.QM31 {
	return m31.QM31{
		AReal: m31.M31{Limb: frontend.Variable(raw[0])},
		AImag: m31.M31{Limb: frontend.Variable(raw[1])},
		BReal: m31.M31{Limb: frontend.Variable(raw[2])},
		BImag: m31.M31{Limb: frontend.Variable(raw[3])},
	}
}
