# SPDX-License-Identifier: Apache-2.0
#
# Rules shared by the module and rail Makefiles. A Makefile sets the
# variables it needs, then includes this file:
#
#   CMDS     binaries under ./cmd to build into BINDIR
#   DEVPKGS  packages that have files behind the edictadev build tag
#   PKGS     packages to test (default ./...)
#   BINDIR   output directory of build (default <repo root>/bin)
#
# Modules never build in parallel: the Makefiles that call each other do so
# one after the other.

export GOWORK := off

GO ?= go
PKGS ?= ./...
MAKE_DIR := $(dir $(lastword $(MAKEFILE_LIST)))
BINDIR ?= $(abspath $(MAKE_DIR)../bin)

.PHONY: test test-q vet test-dev build

test:
	$(GO) test -race -p 2 $(PKGS)

# Package summary lines that failed, plus failure output only.
test-q:
	@$(GO) test -race -count=1 -p 2 $(PKGS) 2>&1 | grep -E '^(--- FAIL|FAIL|panic:)' ; \
	 echo "$(notdir $(CURDIR)): done"

vet:
	$(GO) vet ./...
ifneq ($(strip $(DEVPKGS)),)
	$(GO) vet -tags edictadev $(DEVPKGS)
endif

test-dev:
ifneq ($(strip $(DEVPKGS)),)
	$(GO) test -race -count=1 -tags edictadev $(DEVPKGS)
endif

build:
	@for c in $(CMDS); do echo "go build $$c"; $(GO) build -o $(BINDIR)/$$c ./cmd/$$c || exit 1; done
