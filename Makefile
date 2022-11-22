.PHONY: all build clean get test up down docker

## overridable Makefile variables
# test to run
TESTSET = .
# benchmarks to run
BENCHSET ?= .

# version (defaults to short git hash)
VERSION ?= $(shell git rev-parse --short=8 HEAD)

# use correct sed for platform
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    SED := gsed
else
    SED := sed
endif

PKG_NAME=github.com/craftyc0der/gqlgen-dynamodb

LDFLAGS := -X "${PKG_NAME}/internal/version.Version=${VERSION}"
LDFLAGS += -X "${PKG_NAME}/internal/version.BuildTS=$(shell date -u '+%Y-%m-%d %I:%M:%S')"
LDFLAGS += -X "${PKG_NAME}/internal/version.GitCommit=$(shell git rev-parse --short=8 HEAD)"
LDFLAGS += -X "${PKG_NAME}/internal/version.GitBranch=$(shell git rev-parse --abbrev-ref HEAD)"

GO       := GO111MODULE=on GOPRIVATE=github.com/craftyc0der GOSUMDB=off go
GOBUILD  := CGO_ENABLED=0 $(GO) build $(BUILD_FLAG)
GOTEST   := $(GO) test -gcflags='-l' -p 3

CURRENT_DIR := $(shell pwd)
FILES    := $(shell find internal -name '*.go' -type f -not -name '*.pb.go' -not -name '*_generated.go' -not -name '*_test.go')
TESTS    := $(shell find internal -name '*.go' -type f -not -name '*.pb.go' -not -name '*_generated.go' -name '*_test.go')

DATABASE_BIN := bin/gqlgen-dynamodb

DOCKER_IMAGE_TAG ?= gqlgen-dynamodb:latest

default: clean build

lint:
	$(GOPATH)/bin/staticcheck .

build: clean $(DATABASE_BIN)

$(DATABASE_BIN):
	CGO_ENABLED=0 GOOS=linux go build -ldflags '$(LDFLAGS)' -a -installsuffix cgo -o $(DATABASE_BIN) .

dist:
	CGO_ENABLED=0 GOOS=linux go build -ldflags '$(LDFLAGS)' -a -installsuffix cgo -o $(DATABASE_BIN) .
	CGO_ENABLED=0 GOOS=darwin go build -ldflags '$(LDFLAGS)' -a -installsuffix cgo -o $(DATABASE_BIN)-darwin .

clean:
	rm -f $(DATABASE_BIN)*

generate:
	rm -f ./graph/schema.resolvers.go
	go generate ./...
	make get

get:
	$(GO) get ./...
	$(GO) mod verify
	$(GO) mod tidy

update:
	$(GO) get -u -v all
	$(GO) mod verify
	$(GO) mod tidy

run: default
	./$(DATABASE_BIN)

run-fast:
	$(GO) run ./server.go

run-local: test-database-down test-database-delete test-database-up test
	export LOCAL=http://localhost:8000;export AWS_ACCESS_KEY_ID=dunny;export AWS_SECRET_ACCESS_KEY=dummy;$(GO) run ./server.go

run-docker: test-database-down test-database-delete test-database-up test docker test-docker-up

test-database-up:
	docker compose --project-directory ./database up --detach

test-docker-up:
	docker compose --profile compiled --profile agent --project-directory ./database up

test-database-down:
	docker compose --project-directory ./database down --remove-orphans

test-database-delete:
	rm -f ./database/dynamo/shared-local-instance.db

test:
	$(GO) clean -testcache
	$(GOTEST) -run=$(TESTSET) ./...
	@echo
	@echo Configured tests ran ok.

docker:
	docker build -t $(DOCKER_IMAGE_TAG) .

trivy: docker
	trivy $(DOCKER_IMAGE_TAG)
	dockle $(DOCKER_IMAGE_TAG)
