PKG = github.com/k1LoW/tcprxy
COMMIT = $$(git describe --tags --always)
OSNAME=${shell uname -s}
ifeq ($(OSNAME),Darwin)
	DATE = $$(gdate --utc '+%Y-%m-%d_%H:%M:%S')
else
	DATE = $$(date --utc '+%Y-%m-%d_%H:%M:%S')
endif

BUILD_LDFLAGS = -X $(PKG).commit=$(COMMIT) -X $(PKG).date=$(DATE)
RELEASE_BUILD_LDFLAGS = -s -w $(BUILD_LDFLAGS)

POSTGRES_PORT=54322
POSTGRES_USER=postgres
POSTGRES_PASSWORD=pgpass
POSTGRES_DB=testdb

MYSQL_PORT=33066
MYSQL_DATABASE=testdb
MYSQL_ROOT_PASSWORD=mypass

default: test
ci: depsdev test integration

test:
	go test -cover -v $(shell go list ./... | grep -v vendor)

integration: build
	./tcprxy server -l localhost:54321 -r localhost:$(POSTGRES_PORT) -d pg &
	@sleep 1
	PGPASSWORD=$(POSTGRES_PASSWORD) pgbench -h 127.0.0.1 -p 54321 -U$(POSTGRES_USER) -i $(POSTGRES_DB)
	PGPASSWORD=$(POSTGRES_PASSWORD) pgbench -h 127.0.0.1 -p 54321 -U$(POSTGRES_USER) -c 100 -t 10 $(POSTGRES_DB) 2>&1 > ./result
	kill `cat ./tcprxy.pid`
	@sleep 1
	cat ./result
	@cat ./result | grep "number of transactions actually processed: 1000/1000" || exit 1
	test `grep -c '' ./tcprxy.log` -eq 3 || (cat ./tcprxy.log && exit 1)
	rm ./result
	./tcprxy server -l localhost:33065 -r localhost:$(MYSQL_PORT) -d mysql &
	@sleep 1
	kill `cat ./tcprxy.pid`
	@sleep 1
	test `grep -c '' ./tcprxy.log` -eq 6 || (cat ./tcprxy.log && exit 1)

cover: depsdev
	goveralls -service=travis-ci

build:
	go build -ldflags="$(BUILD_LDFLAGS)"

deps:
	go get -u github.com/golang/dep/cmd/dep
	dep ensure

depsdev: deps
	go get golang.org/x/tools/cmd/cover
	go get github.com/mattn/goveralls
	go get github.com/golang/lint/golint
	go get github.com/motemen/gobump/cmd/gobump
	go get github.com/Songmu/goxz/cmd/goxz
	go get github.com/tcnksm/ghr
	go get github.com/Songmu/ghch/cmd/ghch

crossbuild: deps depsdev
	$(eval ver = v$(shell gobump show -r version/))
	goxz -pv=$(ver) -arch=386,amd64 -build-ldflags="$(RELEASE_BUILD_LDFLAGS)" \
	  -d=./dist/$(ver)

prerelease:
	$(eval ver = v$(shell gobump show -r version/))
	ghch -w -N ${ver}

release: crossbuild
	$(eval ver = v$(shell gobump show -r version/))
	ghr -username k1LoW -replace ${ver} dist/${ver}

.PHONY: default test deps cover
