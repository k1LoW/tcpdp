PKG = github.com/k1LoW/tcpdp
COMMIT = $$(git describe --tags --always)
OSNAME=${shell uname -s}
ifeq ($(OSNAME),Darwin)
	export LO = lo0
	export MYSQL_DISABLE_SSL = --ssl-mode=DISABLED
  export GOMPLATE_OS=darwin
else
	export LO = lo
	export MYSQL_DISABLE_SSL = --ssl-mode=DISABLED
	export GOMPLATE_OS=linux
endif

export GO111MODULE=on

BUILD_LDFLAGS = -X $(PKG).commit=$(COMMIT)
RELEASE_BUILD_LDFLAGS = -s -w $(BUILD_LDFLAGS)

SOURCES=Makefile CHANGELOG.md README.md LICENSE go.mod go.sum dumper logger reader server cmd version main.go

export POSTGRES_PORT=54322
export POSTGRES_USER=postgres
export POSTGRES_PASSWORD=pgpass
export POSTGRES_DB=testdb

export MYSQL_PORT=33066
export MYSQL_DATABASE=testdb
export MYSQL_ROOT_PASSWORD=mypass

default: build
ci: depsdev test_race test_with_integration sec

test:
	go test -v $(shell go list ./... | grep -v misc) -coverprofile=coverage.out -covermode=count

sec:
	gosec ./...

test_race:
	go test $(shell go list ./... | grep -v misc) -race

test_with_integration: build
	go test -v $(shell go list ./... | grep -v misc) -tags integration -coverprofile=coverage-integration.out -covermode=count

build:
	go build -ldflags="$(BUILD_LDFLAGS)"

depsdev:
	go install github.com/Songmu/ghch/cmd/ghch@latest
	go install github.com/Songmu/gocredits/cmd/gocredits@latest
	go install github.com/securego/gosec/v2/cmd/gosec@latest
	go install github.com/tcnksm/ghr@latest
	go install github.com/hairyhenderson/gomplate/v3/cmd/gomplate@v3.9.0
	go install github.com/x-motemen/gobump/cmd/gobump@master

prerelease_for_tagpr:
	gocredits -w .
	git add CHANGELOG.md CREDITS go.mod go.sum

release:
	ghr -username k1LoW -replace ${ver} dist/

.PHONY: default test
