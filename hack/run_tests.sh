#!/usr/bin/env bash

# Copyright 2025 Flant JSC
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

source "$(pwd)/hack/utils.sh"

check_all_deps
check_go

run_tests=""

if [ -n "$RUN_TEST" ]; then
  echo "Found RUN_TEST env. Run only $RUN_TEST test"
  run_tests="-run $RUN_TEST"
fi

run_dir="$(pwd)"
packages="$(go list ./... | grep -v /validation/)"
prefix="$(grep -oP 'module .*$' go.mod | sed 's|module ||')"

if [ -z "$(trim_spaces "$packages")" ]; then
  echo -e '\033[1;33m!!!\033[0m'
  echo -e "\033[1;33mNot found packages in $run_dir with module ${prefix}. Skip go tests\033[0m"
  echo -e '\033[1;33m!!!\033[0m'
  exit 0
fi

echo "Found packages: ${packages[@]} in $run_dir with module $prefix"

while IFS= read -r p; do
  pkg_dir="${p#$prefix}"
  if [ -z "$pkg_dir" ]; then
    echo "Package $p cannot have dir after trim $prefix"
    exit 1
  fi
  full_pkg_path="${run_dir}${pkg_dir}"
  echo "Run tests in $full_pkg_path"
  cd "$full_pkg_path"
  echo "test -v -p 1 $run_tests" | xargs go
done <<< "$packages"