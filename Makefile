MAKEFLAGS += --warn-undefined-variables
SHELL := /bin/bash
.SHELLFLAGS := -o pipefail -euc
.DEFAULT_GOAL := build

PROJECT := registry-monitor
IMPORT_PATH := github.com/coreos/${PROJECT}
IMAGE_NAME := quay.io/coreos/${PROJECT}
DEV_IMAGE := ${PROJECT}_dev

DOCKERRUN := docker run --rm -i \
	-e PROJECT="${PROJECT}" \
	-v /${PROJECT}/vendor:/go/src \
	-v /${PROJECT}:/${PROJECT}/src/${IMPORT_PATH} \
	-w /${PROJECT}/src/${IMPORT_PATH} \
	${DEV_IMAGE}

# ----------------------------------------------
# build

# default top-level target
.PHONY: build
build: build/dev

.PHONY: build/dev
build/dev: vendor *.go
	@rm -rf bin/
	@mkdir -p bin
	${DOCKERRUN} go build -a -tags netgo -ldflags '-w' -o bin/monitor monitor.go

# builds the builder container
.PHONY: build/image_build
build/image_build:
	@echo "Building dev container"
	@docker build --quiet -t ${DEV_IMAGE} -f Dockerfile.dev .

# top-level target for vendoring our packages: glide install requires
# being in the package directory so we have to run this for each package
.PHONY: vendor
vendor: build/image_build
	${DOCKERRUN} glide install --skip-test

# fetch a dependency via go get, vendor it, and then save into the parent
# package's glide.yml
# usage: DEP=github.com/owner/package make add-dep
.PHONY: add-dep
add-dep: build/image_build
ifeq ($(strip $(DEP)),)
	$(error "No dependency provided. Expected: DEP=<go import path>")
endif
	${DOCKERRUN} glide get --skip-test ${DEP}

.PHONY: dist
dist: build
	docker build -t ${IMAGE_NAME} .
