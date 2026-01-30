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

package config

const DefaultPort = 22

type validateOptions struct {
	omitDocInError  bool
	strictUnmarshal bool
	requiredSSHHost bool
	noPrettyError   bool
}

type ValidateOption func(o *validateOptions)

func ParseWithOmitDocInError(v bool) ValidateOption {
	return func(o *validateOptions) {
		o.omitDocInError = v
	}
}

func ParseWithStrictUnmarshal(v bool) ValidateOption {
	return func(o *validateOptions) {
		o.strictUnmarshal = v
	}
}

func ParseWithRequiredSSHHost(v bool) ValidateOption {
	return func(o *validateOptions) {
		o.requiredSSHHost = v
	}
}

func ParseWithNoPrettyError(v bool) ValidateOption {
	return func(o *validateOptions) {
		o.noPrettyError = v
	}
}
