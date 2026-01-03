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

source "$(pwd)/hack/utils.sh"

check_docker

function get_tests_containers() {
  docker container ls --filter='name=test_lib_connection.*' --format='{{.ID}}'
}

function rm_containers() {
  echo "Remove containers $@"
  docker container rm -f "$@"
  return $?
}

function get_tests_networks() {
  docker network ls --filter='name=test_lib_connection.*' --format='{{.Name}}'
}

function rm_networks() {
  echo "Remove networks $@"
  docker network rm "$@"
  return $?
}

do_in_cycle "remove tests containers" get_tests_containers rm_containers
do_in_cycle "remove tests networks" get_tests_networks rm_networks

echo "Docker cleanup done!"
exit 0
