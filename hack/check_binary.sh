#!/usr/bin/env bash

# Copyright 2026 Flant JSC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

binary="$1"
version_arg="$2"
version="$3"

function not_empty_or_exit() {
  if [ -z "$2" ]; then
    echo "$1 is empty"
    exit 1
  fi

  return 0
}

not_empty_or_exit "binary" "$binary"
not_empty_or_exit "version_arg" "$version_arg"
not_empty_or_exit "version" "$version"

binary_full_path="$(pwd)/bin/${binary}"

if [ ! -x "$binary_full_path" ]; then
  echo "$binary_full_path not exists or not executable"
  exit 1
fi

if ! "$binary_full_path" "$version_arg" | grep -q "$version" ; then
  echo "$binary_full_path version not match ${version}. Version is $("$binary_full_path" "$version_arg")"
  exit 1
fi

exit 0
