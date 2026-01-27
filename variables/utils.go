package variables

import (
	"path/filepath"
	"reflect"
	"runtime"
	"strings"

	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
)

const (
	// BitsPerM31 is the number of bits in a M31
	BitsPerM31 = 9
)

// ╔══════════════════════════════════╗
// ║              Fixtures            ║
// ╚══════════════════════════════════╝

const (
	// AllComponents1QueryProofFixture : uses all the components with 1 query (good for quick testing)
	AllComponents1QueryProofFixture = "all_components_one_query.json"
)

// ProofFixturePath returns the path to the proof fixture with the given name.
func ProofFixturePath(name string) string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "test_data", name)
}

// ShapeFixturePath returns the path to the circuit shape fixture derived from the proof fixture.
func ShapeFixturePath(name string) string {
	proofPath := ProofFixturePath(name)
	dir := filepath.Dir(proofPath)
	base := filepath.Base(proofPath)
	ext := filepath.Ext(base)
	shapeName := strings.TrimSuffix(base, ext) + "_shape.json"
	return filepath.Join(dir, shapeName)
}

// ╔══════════════════════════════════╗
// ║         Zeroing Variables        ║
// ╚══════════════════════════════════╝

var (
	frontendVariableType = reflect.TypeOf((*frontend.Variable)(nil)).Elem()
	frontendZeroValue    = reflect.ValueOf(frontend.Variable(0))
	m31QM31Type          = reflect.TypeOf(m31.QM31{})
)

func zeroFrontendVariables(value reflect.Value, skipPublicData bool) {
	if !value.IsValid() {
		return
	}
	switch value.Kind() {
	case reflect.Pointer:
		if value.IsNil() {
			return
		}
		zeroFrontendVariables(value.Elem(), skipPublicData)
	case reflect.Struct:
		valueType := value.Type()
		for i := 0; i < value.NumField(); i++ {
			if skipPublicData && valueType.Field(i).Name == "PublicData" {
				continue
			}
			zeroFrontendVariables(value.Field(i), false)
		}
	case reflect.Interface:
		if value.Type() == frontendVariableType && value.CanSet() {
			value.Set(frontendZeroValue)
		}
	}
}

func zeroInteractionValues(value reflect.Value) {
	if !value.IsValid() {
		return
	}
	switch value.Kind() {
	case reflect.Pointer:
		if value.IsNil() {
			return
		}
		zeroInteractionValues(value.Elem())
	case reflect.Struct:
		if value.Type() == m31QM31Type && value.CanSet() {
			value.Set(reflect.ValueOf(m31.NewQM31Unchecked(0, 0, 0, 0)))
			return
		}
		for i := 0; i < value.NumField(); i++ {
			zeroInteractionValues(value.Field(i))
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < value.Len(); i++ {
			zeroInteractionValues(value.Index(i))
		}
	}
}

// ╔══════════════════════════════════╗
// ║           Miscellaneous          ║
// ╚══════════════════════════════════╝

func convertUintSliceToM31(values []uint64) []m31.M31 {
	if len(values) == 0 {
		return nil
	}

	result := make([]m31.M31, len(values))
	for i, v := range values {
		result[i] = m31.NewM31Unchecked(v)
	}
	return result
}