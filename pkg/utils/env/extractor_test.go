// Copyright 2026 Flant JSC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package env

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtractAll(t *testing.T) {
	type someStruct struct {
		Bool        bool
		String      string
		Int         int
		StringSlice []string
	}

	prefix := "MY"

	appendPrefix := func(envs map[string]string) map[string]string {
		res := make(map[string]string, len(envs))

		for k, v := range envs {
			res[fmt.Sprintf("%s_%s", prefix, k)] = v
		}

		return res
	}

	const (
		BoolEnv   = "BOOL_VAR"
		StringEnv = "STRING_VAR"
		IntEnv    = "INT_VAR"
		SliceEnv  = "SLICE_VAR"
	)

	getExtractor := func(envs map[string]string) *Extractor {
		return NewExtractor(prefix, func(name string) (string, bool) {
			value, ok := envs[name]
			return value, ok
		})
	}

	assertErr := func(e error, contains ...string) {
		if len(contains) == 0 {
			require.NoError(t, e, "should not fail")
			return
		}

		require.Error(t, e, "should fail")
		for _, c := range contains {
			require.Contains(t, e.Error(), c, "error should contains")
		}
	}

	t.Run("not parsed", func(t *testing.T) {
		envsForErrorCases := appendPrefix(map[string]string{
			StringEnv: "incorrect",
			IntEnv:    "incorrect",
		})

		t.Run("has empty name", func(t *testing.T) {
			var str string
			var i int

			extractor := getExtractor(envsForErrorCases)

			err := extractor.ExtractAllVars(
				NewVar(StringEnv, &str),
				NewVar("", &i),
			)

			assertErr(err, "name is empty for env variable 'vars[1]'")
		})

		t.Run("not unique names", func(t *testing.T) {
			dest := someStruct{}

			extractor := getExtractor(envsForErrorCases)

			err := extractor.ExtractAllVars(
				NewVar(StringEnv, &dest.String),
				NewVar(BoolEnv, &dest.Bool),
				NewVar(StringEnv, &dest.String),
				NewVar(IntEnv, &dest.Int),
				NewVar(IntEnv, &dest.Int),
				NewVar(SliceEnv, &dest.StringSlice),
				NewVar(IntEnv, &dest.Int),
			)

			assertErr(
				err,
				"have multiple names 2 for env variable 'STRING_VAR'",
				"have multiple names 3 for env variable 'INT_VAR'",
			)
		})

		t.Run("has nil", func(t *testing.T) {
			var str string

			extractor := getExtractor(envsForErrorCases)

			err := extractor.ExtractAllVars(
				NewVar(StringEnv, &str),
				NewVar(IntEnv, nil),
			)

			assertErr(err, "value is nil for env variable 'INT_VAR'")
		})

		t.Run("has not ptr", func(t *testing.T) {
			var str string
			var i int

			extractor := getExtractor(envsForErrorCases)

			err := extractor.ExtractAllVars(
				NewVar(StringEnv, &str),
				NewVar(IntEnv, i),
			)

			assertErr(err, "value should be pointer for env variable 'INT_VAR'")
		})

		t.Run("has not supported type", func(t *testing.T) {
			type myStruct struct {
				Var int
			}

			t.Run("scalar", func(t *testing.T) {
				var str string
				var my myStruct

				extractor := getExtractor(envsForErrorCases)

				err := extractor.ExtractAllVars(
					NewVar(StringEnv, &str),
					NewVar(IntEnv, &my),
				)

				assertErr(err, "incorrect value pointer type 'struct'. Should be int, string, bool or []string for env variable 'INT_VAR'")
			})

			t.Run("slice", func(t *testing.T) {
				var str string
				var my []myStruct

				extractor := getExtractor(envsForErrorCases)

				err := extractor.ExtractAllVars(
					NewVar(StringEnv, &str),
					NewVar(IntEnv, &my),
				)

				assertErr(err, "incorrect value slice pointer type 'struct'. Should be int, string, bool or []string for env variable 'INT_VAR'")
			})
		})

		t.Run("incorrect int", func(t *testing.T) {
			dest := someStruct{}

			extractor := getExtractor(appendPrefix(map[string]string{
				IntEnv: "1not int",
			}))

			err := extractor.ExtractAllVars(
				NewVar(IntEnv, &dest.Int),
			)

			assertErr(err, "Cannot convert '1not int' to int for MY_INT_VAR")
		})

		t.Run("all errors present", func(t *testing.T) {
			var i int

			extractor := getExtractor(envsForErrorCases)

			err := extractor.ExtractAllVars(
				NewVar(StringEnv, nil),
				NewVar(IntEnv, i),
			)

			assertErr(
				err,
				"value is nil for env variable 'STRING_VAR'",
				"value should be pointer for env variable 'INT_VAR'",
			)
		})
	})

	t.Run("parsed", func(t *testing.T) {
		t.Run("all", func(t *testing.T) {
			dest := someStruct{}

			extractor := getExtractor(appendPrefix(map[string]string{
				StringEnv: "my string",
				IntEnv:    "22",
				BoolEnv:   "true",
				SliceEnv:  "first,second,third",
			}))

			err := extractor.ExtractAllVars(
				NewVar(StringEnv, &dest.String),
				NewVar(IntEnv, &dest.Int),
				NewVar(BoolEnv, &dest.Bool),
				NewVar(SliceEnv, &dest.StringSlice),
			)

			assertErr(err)

			require.Equal(t, "my string", dest.String, "should set val")
			require.Equal(t, 22, dest.Int, "should set val")
			require.True(t, dest.Bool, "should set val")
			require.Equal(t, []string{"first", "second", "third"}, dest.StringSlice, "should set val")
		})

		t.Run("partly set present", func(t *testing.T) {
			dest := someStruct{}

			extractor := getExtractor(appendPrefix(map[string]string{
				BoolEnv:  "",
				SliceEnv: "",
			}))

			presentVals := make([]*Var, 0, 2)

			boolVal := NewVar(BoolEnv, &dest.Bool)
			presentVals = append(presentVals, boolVal)

			sliceVal := NewVar(SliceEnv, &dest.StringSlice)
			presentVals = append(presentVals, sliceVal)

			notPresentsVals := make([]*Var, 0, 2)

			stringVal := NewVar(StringEnv, &dest.String)
			notPresentsVals = append(notPresentsVals, stringVal)

			intVal := NewVar(IntEnv, &dest.Int)
			notPresentsVals = append(notPresentsVals, intVal)

			err := extractor.ExtractAllVars(
				stringVal,
				intVal,
				boolVal,
				sliceVal,
			)

			assertErr(err)

			for _, val := range presentVals {
				require.True(t, val.Present, "should set present for %s", val.Name)
			}

			for _, val := range notPresentsVals {
				require.False(t, val.Present, "should not set present for %s", val.Name)
			}

			require.Empty(t, dest.String, "should not set val")
			require.Equal(t, 0, dest.Int, "should not set val")
			require.False(t, dest.Bool, "should set val")
			require.Equal(t, make([]string, 0), dest.StringSlice, "should set val")
		})

		t.Run("with custom slice separator", func(t *testing.T) {
			dest := someStruct{}

			extractor := getExtractor(appendPrefix(map[string]string{
				SliceEnv: "first;second;third",
			})).WithSliceSeparator(";")

			err := extractor.ExtractAll([]*Var{
				NewVar(SliceEnv, &dest.StringSlice),
			})

			assertErr(err)

			require.Equal(t, []string{"first", "second", "third"}, dest.StringSlice, "should set val")
		})

		t.Run("with custom prefix separator", func(t *testing.T) {
			dest := someStruct{}

			extractor := getExtractor(map[string]string{
				prefix + IntEnv: "-22",
			}).WithPrefixSeparator("")

			err := extractor.ExtractAllVars(
				NewVar(IntEnv, &dest.Int),
			)

			assertErr(err)

			require.Equal(t, -22, dest.Int, "should set val")
		})
	})
}

func TestSimplifyPrefix(t *testing.T) {
	require.Equal(t, "MY", SimplifyPrefix(" MY_"))
}
