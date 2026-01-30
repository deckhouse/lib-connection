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

package utils

import (
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/name212/govalue"
)

type (
	EnvsLookupFunc func(name string) (string, bool)
)

// SimplifyPrefix
// This method trim right all _ ang - symbols and spaces left and right.
func SimplifyPrefix(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	prefix = strings.TrimRight(prefix, "_-")

	return prefix
}

type EnvExtractor struct {
	prefixSeparator string
	sliceSeparator  string
	prefix          string
	lookupFunc      func(string) (string, bool)
}

// NewEnvOsExtractor
// create extractor with os.LookupEnv lookup function
func NewEnvOsExtractor(prefix string) *EnvExtractor {
	return NewEnvExtractor(prefix, os.LookupEnv)
}

// NewEnvExtractor
// utils for extract env and pass to destination
// by default extractor use _ for separate prefix and env name
// if need we use WithPrefixSeparator method for set your own or set to empty
// by default slice string extractor split env string by , symbol
// if need we use WithSliceSeparator method for set your own slice separator
func NewEnvExtractor(prefix string, lookupFunc EnvsLookupFunc) *EnvExtractor {
	return &EnvExtractor{
		prefixSeparator: "_",
		sliceSeparator:  ",",
		prefix:          prefix,
		lookupFunc:      lookupFunc,
	}
}

// WithSliceSeparator
// set only not empty string
func (e *EnvExtractor) WithSliceSeparator(s string) *EnvExtractor {
	if s != "" {
		e.sliceSeparator = s
	}

	return e
}

func (e *EnvExtractor) WithPrefixSeparator(s string) *EnvExtractor {
	e.prefixSeparator = s
	return e
}

func (e *EnvExtractor) AddEnvToUsage(usage string, envName string) string {
	if envName == "" {
		return usage
	}

	return fmt.Sprintf("%s (Can rewrite with %s env)", usage, e.nameWithPrefix(envName))
}

func (e *EnvExtractor) Int(name string, destination *int) (bool, error) {
	strVar, ok := e.getVar(name)
	if !ok {
		return false, nil
	}

	value, err := strconv.Atoi(strVar)
	if err != nil {
		return false, fmt.Errorf("Cannot convert '%s' to int for %s: %w", strVar, e.nameWithPrefix(name), err)
	}

	*destination = value

	return true, nil
}

func (e *EnvExtractor) StringWithoutPrefix(name string, destination *string) bool {
	strVar, ok := e.lookupFunc(name)
	if !ok {
		return false
	}

	*destination = strVar

	return true
}

func (e *EnvExtractor) String(name string, destination *string) bool {
	strVar, ok := e.getVar(name)
	if !ok {
		return false
	}

	*destination = strVar

	return true
}

func (e *EnvExtractor) Strings(name string, destination *[]string) bool {
	valsStr, ok := e.getVar(name)
	if !ok {
		return false
	}

	valsSplit := strings.Split(valsStr, e.sliceSeparator)
	vals := make([]string, 0, len(valsSplit))
	for _, v := range valsSplit {
		if strings.TrimSpace(v) != "" {
			vals = append(vals, v)
		}
	}

	*destination = vals

	return true
}

// Bool
// returns that env is set
func (e *EnvExtractor) Bool(name string, destination *bool) bool {
	strVar, ok := e.getVar(name)
	if !ok {
		return false
	}
	value := strVar != ""

	*destination = value

	return true
}

func (e *EnvExtractor) nameWithPrefix(name string) string {
	if e.prefix != "" {
		name = fmt.Sprintf("%s%s%s", e.prefix, e.prefixSeparator, name)
	}

	return name
}

func (e *EnvExtractor) getVar(name string) (string, bool) {
	return e.lookupFunc(e.nameWithPrefix(name))
}

type EnvVar struct {
	Destination any
	Present     bool
}

func NewEnvVar(destination any) *EnvVar {
	return &EnvVar{
		Destination: destination,
	}
}

type EnvVarsMap = map[string]*EnvVar

// ExtractAll
// extract all envs from map
// if env present but have empty value set EnvVar Present field to true
// you can process it if need
// ExtractAll found need type for Destination, but destination should be pointer
// Warning! if error returned some Destination can be set
func (e *EnvExtractor) ExtractAll(envsToPointers EnvVarsMap) error {
	var errs *multierror.Error
	appendError := func(envName string, msg string) {
		errs = multierror.Append(errs, fmt.Errorf("%s for env variable '%s'", msg, envName))
	}

	for name, val := range envsToPointers {
		valAny := val.Destination

		if govalue.Nil(valAny) {
			appendError(name, "value is nil")
			continue
		}

		v := reflect.ValueOf(valAny)

		if v.Kind() != reflect.Ptr {
			appendError(name, "value should be pointer")
			continue
		}

		if v.IsNil() {
			appendError(name, "value is nil")
			continue
		}

		elem := v.Elem()
		kind := v.Type().Elem().Kind()
		switch kind {
		case reflect.Int:
			var destInt int

			present, err := e.Int(name, &destInt)
			if err != nil {
				appendError(name, err.Error())
				continue
			}

			elem.SetInt(int64(destInt))
			val.Present = present
		case reflect.String:
			strDest := ""
			val.Present = e.String(name, &strDest)
			elem.SetString(strDest)
		case reflect.Bool:
			var destBool bool
			val.Present = e.Bool(name, &destBool)
			elem.SetBool(destBool)
		case reflect.Slice:
			if err := e.processSlice(name, elem, val); err != "" {
				appendError(name, err)
			}
		default:
			appendError(name, incorrectValErr(kind, false))
		}
	}

	return errs.ErrorOrNil()
}

func (e *EnvExtractor) processSlice(name string, slice reflect.Value, val *EnvVar) string {
	kind := slice.Type().Elem().Kind()
	switch kind {
	case reflect.String:
		var destStrSlice []string
		val.Present = e.Strings(name, &destStrSlice)
		slice.Set(reflect.ValueOf(destStrSlice))
	default:
		return incorrectValErr(kind, true)
	}

	return ""
}

func incorrectValErr(kind reflect.Kind, isSlice bool) string {
	msg := []string{
		"incorrect value",
	}

	if isSlice {
		msg = append(msg, "slice")
	}

	msg = append(msg, fmt.Sprintf("pointer type '%s'. Should be int, string, bool or []string", kind))

	return strings.Join(msg, " ")
}
