PKG = github.com/k1LoW/tcpdp
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
	./tcpdp proxy -l localhost:54321 -r localhost:$(POSTGRES_PORT) -d pg &
	@sleep 1
	PGPASSWORD=$(POSTGRES_PASSWORD) pgbench -h 127.0.0.1 -p 54321 -U$(POSTGRES_USER) -i $(POSTGRES_DB)
	PGPASSWORD=$(POSTGRES_PASSWORD) pgbench -h 127.0.0.1 -p 54321 -U$(POSTGRES_USER) -c 100 -t 10 $(POSTGRES_DB) 2>&1 > ./result
	kill `cat ./tcpdp.pid`
	@sleep 1
	cat ./result
	@cat ./result | grep "number of transactions actually processed: 1000/1000" || (echo "pgbench faild" && exit 1)
	test `grep -c '' ./tcpdp.log` -eq 4 || (cat ./tcpdp.log && exit 1)
	rm ./result
	./tcpdp proxy -l localhost:33065 -r localhost:$(MYSQL_PORT) -d mysql &
	@sleep 1
	mysqlslap --no-defaults --concurrency=100 --iterations=1 --auto-generate-sql --auto-generate-sql-add-autoincrement --auto-generate-sql-load-type=mixed --auto-generate-sql-write-number=100 --number-of-queries=1000 --host=127.0.0.1 --port=33065 --user=root --password=$(MYSQL_ROOT_PASSWORD) --skip-ssl 2>&1 > ./result
	kill `cat ./tcpdp.pid`
	@sleep 1
	cat ./result
	@cat ./result | grep "Number of clients running queries: 100" || (echo "mysqlslap faild" && exit 1)
	test `grep -c '' ./tcpdp.log` -eq 8 || (cat ./tcpdp.log && exit 1)

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
	go get github.com/karalabe/xgo

crossbuild: deps depsdev
	$(eval ver = v$(shell gobump show -r version/))
	goxz -pv=$(ver) -os=darwin -build-ldflags="$(RELEASE_BUILD_LDFLAGS)" \
	  -d=./dist/$(ver)
	docker build -t karalabe/xgo-latest .
	xgo --targets=linux/amd64 -ldflags="$(RELEASE_BUILD_LDFLAGS)" github.com/k1LoW/tcpdp
	mkdir tcpdp_$(ver)_linux_amd64
	mv tcpdp-linux-amd64 ./tcpdp_$(ver)_linux_amd64/tcpdp
	cp CHANGELOG.md README.md LICENSE ./tcpdp_$(ver)_linux_amd64
	COPYFILE_DISABLE=1 tar -zcvf ./dist/$(ver)/tcpdp_$(ver)_linux_amd64.tar.gz ./tcpdp_$(ver)_linux_amd64
	rm -rf ./tcpdp_$(ver)_linux_amd64

prerelease:
	$(eval ver = v$(shell gobump show -r version/))
	ghch -w -N ${ver}

release: crossbuild
	$(eval ver = v$(shell gobump show -r version/))
	ghr -username k1LoW -replace ${ver} dist/${ver}

.PHONY: default test deps cover
