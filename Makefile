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

SHELL = /usr/bin/env bash

GOLANGCI_VERSION = 2.7.2
GOFUMPT_VERSION=0.9.2
JQ_VERSION=1.7.1

PLATFORM_NAME := $(shell uname -m)

OS_NAME := $(shell uname)
ifndef OS
	ifeq ($(UNAME), Linux)
		OS = linux
	else ifeq ($(UNAME), Darwin)
		OS = darwin
	endif
endif

# Set platform for deps
ifeq ($(OS_NAME), Linux)
	GOFUMPT_PLATFORM = linux
	JQ_PLATFORM = linux
else ifeq ($(OS_NAME), Darwin)
	GOFUMPT_PLATFORM = darwin
	JQ_PLATFORM = macos
endif

# Set arch for deps
ifeq ($(PLATFORM_NAME), x86_64)
	GOFUMPT_ARCH = amd64
	JQ_PLATFORM_ARCH = $(JQ_PLATFORM)-amd64
else ifeq ($(PLATFORM_NAME), arm64)
	GOFUMPT_ARCH = arm64
	JQ_PLATFORM_ARCH = $(JQ_PLATFORM)-arm64
endif

.PHONY: bin/jq bin/gofumpt bin/golangci-lint clean validation/license/download

bin:
	mkdir -p bin

curl-installed:
	command -v curl > /dev/null

go-installed:
	command -v go
	go version

bin/jq: curl-installed bin
	curl -sSfL https://github.com/jqlang/jq/releases/download/jq-$(JQ_VERSION)/jq-$(JQ_PLATFORM_ARCH) -o ./bin/jq
	@chmod +x "./bin/jq"

bin/golangci-lint: curl-installed bin
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | BINARY=golangci-lint bash -s -- v${GOLANGCI_VERSION}
	@chmod +x "./bin/golangci-lint"

bin/gofumpt: curl-installed bin
	curl -sSfLo "bin/gofumpt" https://github.com/mvdan/gofumpt/releases/download/v$(GOFUMPT_VERSION)/gofumpt_v$(GOFUMPT_VERSION)_$(GOFUMPT_PLATFORM)_$(GOFUMPT_ARCH)
	@chmod +x "./bin/gofumpt"

deps: bin bin/jq bin/golangci-lint bin/gofumpt

test: go-installed
	./hack/run_tests.sh

lint: bin/golangci-lint
	./bin/golangci-lint run ./... -c .golangci.yaml

lint/fix: bin/golangci-lint
	./bin/golangci-lint run ./... -c .golangci.yaml --fix

fmt: bin/gofumpt
	 find . -type f -name '*.go' -not -path "./validation*" -print0 | xargs -0 ./bin/gofumpt -l

validation/license/dir:
	mkdir -p validation

validation/license/download: curl-installed validation/license/dir bin/jq
	set -o pipefail; \
	  curl -sL https://api.github.com/repos/deckhouse/deckhouse/contents/tools/validation \
	  | ./bin/jq 'map(select(.type == "file")) | map(select(.name | test(".*.go")))' \
	  | ./bin/jq -r '.[] | ["curl -sSfLo \"validation/\(.name)\" \"\(.download_url)\""] | join("\n")' \
	  | while IFS= read -r command_to_run; do echo "run: $$command_to_run"; $(SHELL) -c "$$command_to_run"; done

validation/license: go-installed validation/license/download
	cd ./validation; declare -a validation_deps=("github.com/tidwall/gjson" "gopkg.in/yaml.v2"); \
		for i in "${validation_deps[@]}"; do \
		  go get "$$i"; \
		done
	go run ./validation/{main,messages,diff,copyright,no_cyrillic,doc_changes,grafana_dashboard,release_requirements}.go -type copyright
	# prevent goland ide errors
	rm -f ./validation/go.mod ./validation/go.sum

all: bin deps validation/license fmt lint test

clean:
	rm -rf ./bin
	rm -rf ./validation
