PKG = github.com/k1LoW/tcpdp
COMMIT = $$(git describe --tags --always)
OSNAME=${shell uname -s}
ifeq ($(OSNAME),Darwin)
	LO = "lo0"
else
	LO = "lo"
endif

ifeq ("$(shell uname)","Darwin")
GO ?= GO111MODULE=on go
else
GO ?= GO111MODULE=on /usr/local/go/bin/go
endif

BUILD_LDFLAGS = -X $(PKG).commit=$(COMMIT)
RELEASE_BUILD_LDFLAGS = -s -w $(BUILD_LDFLAGS)

POSTGRES_PORT=54322
POSTGRES_USER=postgres
POSTGRES_PASSWORD=pgpass
POSTGRES_DB=testdb

MYSQL_PORT=33066
MYSQL_DATABASE=testdb
MYSQL_ROOT_PASSWORD=mypass

DISTS=centos7 centos6 ubuntu16

default: test
ci: depsdev test proxy_integration probe_integration read_integration

test:
	$(GO) test -cover -v $(shell go list ./... | grep -v vendor)

proxy_integration: build
	sudo rm -f ./tcpdp.log*
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

probe_integration: build
	sudo rm -f ./tcpdp.log*
	sudo ./tcpdp probe -i $(LO) -t $(POSTGRES_PORT) -d pg &
	@sleep 1
	PGPASSWORD=$(POSTGRES_PASSWORD) pgbench -h 127.0.0.1 -p $(POSTGRES_PORT) -U$(POSTGRES_USER) -i $(POSTGRES_DB)
	PGPASSWORD=$(POSTGRES_PASSWORD) pgbench -h 127.0.0.1 -p $(POSTGRES_PORT) -U$(POSTGRES_USER) -c 100 -t 10 $(POSTGRES_DB) 2>&1 > ./result
	sudo kill `cat ./tcpdp.pid`
	@sleep 1
	cat ./result
	@cat ./result | grep "number of transactions actually processed: 1000/1000" || (echo "pgbench faild" && exit 1)
	test `grep -c '' ./tcpdp.log` -eq 4 || (cat ./tcpdp.log && exit 1)
	rm ./result
	sudo ./tcpdp probe -i $(LO) -t $(MYSQL_PORT) -d mysql &
	@sleep 1
	mysqlslap --no-defaults --concurrency=100 --iterations=1 --auto-generate-sql --auto-generate-sql-add-autoincrement --auto-generate-sql-load-type=mixed --auto-generate-sql-write-number=100 --number-of-queries=1000 --host=127.0.0.1 --port=$(MYSQL_PORT) --user=root --password=$(MYSQL_ROOT_PASSWORD) --skip-ssl 2>&1 > ./result
	sudo kill `cat ./tcpdp.pid`
	@sleep 1
	cat ./result
	@cat ./result | grep "Number of clients running queries: 100" || (echo "mysqlslap faild" && exit 1)
	test `grep -c '' ./tcpdp.log` -eq 8 || (cat ./tcpdp.log && exit 1)

read_integration: build
	./tcpdp read -t $(POSTGRES_PORT) -d pg test/pcap/pg_prepare.pcap > ./result
	test `grep -c '' ./result` -eq 20 || (cat ./result && exit 1)
	./tcpdp read -t $(MYSQL_PORT) -d mysql test/pcap/mysql_prepare.pcap > ./result
	test `grep -c '' ./result` -eq 20 || (cat ./result && exit 1)

cover: depsdev
	goveralls -service=travis-ci

build:
	$(GO) build -ldflags="$(BUILD_LDFLAGS)"

build_darwin: depsdev
	$(eval ver = v$(shell gobump show -r version/))
	$(eval pkg = tcpdp_v$(shell gobump show -r version/)_darwin_amd64)
	$(GO) build -ldflags="$(RELEASE_BUILD_LDFLAGS) -X $(PKG).version=$(ver)"
	[ -d ./dist/$(ver) ] || mkdir ./dist/$(ver)
	mkdir $(pkg)
	mv tcpdp ./$(pkg)/tcpdp
	cp CHANGELOG.md README.md LICENSE ./$(pkg)
	tar -zcvf ./dist/$(ver)/$(pkg).tar.gz --exclude='*/.*' ./$(pkg)
	rm -rf ./$(pkg)

build_in_docker:
	$(eval ver = v$(shell gobump show -r version/))
	$(eval pkg = tcpdp_v$(shell gobump show -r version/)_linux_amd64.$(DIST))
	$(GO) build -ldflags="$(RELEASE_BUILD_LDFLAGS) -X $(PKG).version=$(ver)"
	[ -d ./dist/$(ver) ] || mkdir ./dist/$(ver)
	mkdir $(pkg)
	mv tcpdp ./$(pkg)/tcpdp
	cp CHANGELOG.md README.md LICENSE ./$(pkg)
	tar -zcvf ./dist/$(ver)/$(pkg).tar.gz ./$(pkg)
	rm -rf ./$(pkg)

build_static_in_docker:
	$(eval ver = v$(shell gobump show -r version/))
	$(eval pkg = tcpdp_v$(shell gobump show -r version/)_linux_amd64_static.$(DIST))
	cd /usr/local/src/libpcap-$(LIBPCAP_VERSION) && ./configure && make && make install
	$(GO) build -a -tags netgo -installsuffix netgo -ldflags="$(RELEASE_BUILD_LDFLAGS) -X $(PKG).version=$(ver) -X $(PKG).libpcap=$(LIBPCAP_VERSION) -linkmode external -extldflags -static"
	[ -d ./dist/$(ver) ] || mkdir ./dist/$(ver)
	mkdir $(pkg)
	mv tcpdp ./$(pkg)/tcpdp
	cp CHANGELOG.md README.md LICENSE ./$(pkg)
	tar -zcvf ./dist/$(ver)/$(pkg).tar.gz ./$(pkg)
	rm -rf ./$(pkg)

depsdev:
	$(GO) get golang.org/x/tools/cmd/cover
	$(GO) get github.com/mattn/goveralls
	$(GO) get github.com/golang/lint/golint
	$(GO) get github.com/motemen/gobump/cmd/gobump
	$(GO) get github.com/tcnksm/ghr
	$(GO) get github.com/Songmu/ghch/cmd/ghch

crossbuild: build_darwin
	@for d in $(DISTS); do\
		docker-compose up $$d;\
	done

prerelease:
	$(eval ver = v$(shell gobump show -r version/))
	ghch -w -N ${ver}

release:
	$(eval ver = v$(shell gobump show -r version/))
	ghr -username k1LoW -replace ${ver} dist/${ver}

docker:
	docker build -t tcpdp_develop -f dockerfiles/Dockerfile.golang .
	docker run --cap-add=SYS_PTRACE --security-opt="seccomp=unconfined" -v $(GOPATH):/go/ -v $(GOPATH)/pkg/mod/cache:/go/pkg/mod/cache -w /go/src/github.com/k1LoW/tcpdp -it tcpdp_develop /bin/bash


.PHONY: default test cover
