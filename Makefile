PKG = github.com/k1LoW/tcpdp
COMMIT = $$(git describe --tags --always)
OSNAME=${shell uname -s}
ifeq ($(OSNAME),Darwin)
	export LO = lo0
	export MYSQL_DISABLE_SSL_ = --ssl-mode=DISABLED
else
	export LO = lo
	export MYSQL_DISABLE_SSL_ = --skip-ssl
endif

GO ?= GO111MODULE=on go

BUILD_LDFLAGS = -X $(PKG).commit=$(COMMIT)
RELEASE_BUILD_LDFLAGS = -s -w $(BUILD_LDFLAGS)

BINDIR=/usr/local/bin
SOURCES=Makefile CHANGELOG.md README.md LICENSE go.mod go.sum dumper logger reader server cmd version main.go

export POSTGRES_PORT=54322
export POSTGRES_USER=postgres
export POSTGRES_PASSWORD=pgpass
export POSTGRES_DB=testdb

export MYSQL_PORT=33066
export MYSQL_DATABASE=testdb
export MYSQL_ROOT_PASSWORD=mypass

DISTS=centos7 centos6 ubuntu16

default: build
ci: depsdev test_with_integration probe_integration read_integration long_query_integration

lint:
	golint $(shell go list ./... | grep -v misc)
	$(GO) vet $(shell go list ./... | grep -v misc)
	$(GO) fmt $(shell go list ./... | grep -v misc)

test:
	$(GO) test -v $(shell go list ./... | grep -v misc) -coverprofile=coverage.txt -covermode=count

test_with_integration: build
	$(GO) test -v $(shell go list ./... | grep -v misc) -tags integration -coverprofile=coverage.txt -covermode=count

probe_integration: build
	@sudo rm -f ./tcpdp.log* ./dump.log*
	sudo ./tcpdp probe -i $(LO) -t $(POSTGRES_PORT) -d pg -B 64MB &
	@sleep 1
	PGPASSWORD=$(POSTGRES_PASSWORD) pgbench -h 127.0.0.1 -p $(POSTGRES_PORT) -U$(POSTGRES_USER) -i $(POSTGRES_DB)
	PGPASSWORD=$(POSTGRES_PASSWORD) pgbench -h 127.0.0.1 -p $(POSTGRES_PORT) -U$(POSTGRES_USER) -c 100 -t 10 $(POSTGRES_DB) 2>&1 > ./result
	@sudo kill `cat ./tcpdp.pid`
	@sleep 1
	@cat ./result
	@cat ./result | grep "number of transactions actually processed: 1000/1000" || (echo "pgbench faild" && exit 1)
	test `grep -c '' ./tcpdp.log` -eq 4 || (cat ./tcpdp.log && exit 1)
	@rm ./result
	@sudo rm -f ./tcpdp.log* ./dump.log*
	sudo ./tcpdp probe -i $(LO) -t $(MYSQL_PORT) -d mysql -B 64MB &
	@sleep 1
	mysqlslap --no-defaults --concurrency=100 --iterations=1 --auto-generate-sql --auto-generate-sql-add-autoincrement --auto-generate-sql-load-type=mixed --auto-generate-sql-write-number=100 --number-of-queries=1000 --host=127.0.0.1 --port=$(MYSQL_PORT) --user=root --password=$(MYSQL_ROOT_PASSWORD) $(MYSQL_DISABLE_SSL) 2>&1 > ./result
	@sudo kill `cat ./tcpdp.pid`
	@sleep 1
	@cat ./result
	@cat ./result | grep "Number of clients running queries: 100" || (echo "mysqlslap faild" && exit 1)
	test `grep -c '' ./tcpdp.log` -eq 4 || (cat ./tcpdp.log && exit 1)
	@sudo rm -f ./tcpdp.log* ./dump.log*
	@echo "probe_integration OK"

read_integration: build
	./tcpdp read -t $(POSTGRES_PORT) -d pg testdata/pcap/pg_prepare.pcap > ./result
	test `grep -c '' ./result` -eq 20 || (cat ./result && exit 1)
	./tcpdp read -t $(MYSQL_PORT) -d mysql testdata/pcap/mysql_prepare.pcap > ./result
	test `grep -c '' ./result` -eq 20 || (cat ./result && exit 1)
	@echo "read_integration OK"

long_query_integration: build
	@sudo rm -f ./tcpdp.log* ./dump.log*
	./tcpdp proxy -l localhost:33065 -r localhost:$(MYSQL_PORT) -d mysql &
	@sleep 1
	mysql --host=127.0.0.1 --port=33065 --user=root --password=$(MYSQL_ROOT_PASSWORD) testdb $(MYSQL_DISABLE_SSL) < ./testdata/query/long.sql 2>&1 > /dev/null
	@sudo kill `cat ./tcpdp.pid`
	@sleep 1
	test `grep -c 'query_start' ./dump.log` -eq 1 || (cat ./dump.log && exit 1)
	test `grep -c 'query_last' ./dump.log` -eq 1 || (cat ./dump.log && exit 1)
	@sudo rm -f ./tcpdp.log* ./dump.log*
	@sudo rm -f ./tcpdp.log* ./dump.log*
	sudo ./tcpdp probe -i $(LO) -t $(MYSQL_PORT) -d mysql -B 64MB &
	@sleep 1
	mysql --host=127.0.0.1 --port=$(MYSQL_PORT) --user=root --password=$(MYSQL_ROOT_PASSWORD) testdb $(MYSQL_DISABLE_SSL) < ./testdata/query/long.sql 2>&1 > /dev/null
	@sudo kill `cat ./tcpdp.pid`
	@sleep 1
	test `grep -c 'query_start' ./dump.log` -eq 1 || (cat ./dump.log && exit 1)
	test `grep -c 'query_last' ./dump.log` -eq 1 || (cat ./dump.log && exit 1)
	@sudo rm -f ./tcpdp.log* ./dump.log*
	./tcpdp proxy -l localhost:54321 -r localhost:$(POSTGRES_PORT) -d pg &
	@sleep 1
	PGPASSWORD=$(POSTGRES_PASSWORD) psql -h 127.0.0.1 -p 54321 -U$(POSTGRES_USER) $(POSTGRES_DB) < ./testdata/query/long.sql 2>&1 > /dev/null
	@sudo kill `cat ./tcpdp.pid`
	@sleep 1
	test `grep -c 'query_start' ./dump.log` -eq 1 || (cat ./dump.log && exit 1)
	test `grep -c 'query_last' ./dump.log` -eq 1 || (cat ./dump.log && exit 1)
	@sudo rm -f ./tcpdp.log* ./dump.log*
	sudo ./tcpdp probe -i $(LO) -t $(POSTGRES_PORT) -d pg -B 64MB &
	@sleep 1
	PGPASSWORD=$(POSTGRES_PASSWORD) psql -h 127.0.0.1 -p $(POSTGRES_PORT) -U$(POSTGRES_USER) $(POSTGRES_DB) < ./testdata/query/long.sql 2>&1 > /dev/null
	@sudo kill `cat ./tcpdp.pid`
	@sleep 1
	test `grep -c 'query_start' ./dump.log` -eq 1 || (cat ./dump.log && exit 1)
	test `grep -c 'query_last' ./dump.log` -eq 1 || (cat ./dump.log && exit 1)
	@sudo rm -f ./tcpdp.log* ./dump.log*
	@echo "long_query_integration OK"

build:
	$(GO) build -ldflags="$(BUILD_LDFLAGS)"

install:
	cp tcpdp $(BINDIR)/tcpdp

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

build_rpm:
	$(eval ver = v$(shell gobump show -r version/))
	$(eval no_v_ver = $(shell gobump show -r version/))
	$(eval pkg = tcpdp-$(shell gobump show -r version/))
	$(GO) build -ldflags="$(RELEASE_BUILD_LDFLAGS) -X $(PKG).version=$(ver)"
	cat ./template/tcpdp.spec.template | VERSION=$(no_v_ver) gomplate > tcpdp.spec
	rm -rf /root/rpmbuild/
	rpmdev-setuptree
	yum-builddep tcpdp.spec
	mkdir $(pkg)
	cp -r $(SOURCES) $(pkg)
	tar -zcvf $(pkg).tar.gz ./$(pkg)
	rm -rf $(pkg)
	mv $(pkg).tar.gz /root/rpmbuild/SOURCES
	spectool -g -R tcpdp.spec
	rpmbuild -ba tcpdp.spec
	mv /root/rpmbuild/RPMS/*/*.rpm /go/src/github.com/k1LoW/tcpdp/dist/$(ver)
	rm tcpdp tcpdp.spec

build_deb:
	$(eval ver = v$(shell gobump show -r version/))
	$(eval no_v_ver = $(shell gobump show -r version/))
	$(eval workdir = deb)
	$(GO) build -ldflags="$(RELEASE_BUILD_LDFLAGS) -X $(PKG).version=$(ver)"
	mkdir -p $(workdir)/DEBIAN $(workdir)/usr/bin
	cat ./template/control.template | VERSION=$(no_v_ver) gomplate > $(workdir)/DEBIAN/control
	mv tcpdp $(workdir)/usr/bin
	fakeroot dpkg-deb --build $(workdir) /go/src/github.com/k1LoW/tcpdp/dist/$(ver)
	rm -rf $(workdir)

depsdev:
	GO111MODULE=off go get golang.org/x/tools/cmd/cover
	GO111MODULE=off go get golang.org/x/lint/golint
	GO111MODULE=off go get github.com/motemen/gobump/cmd/gobump
	GO111MODULE=off go get github.com/tcnksm/ghr
	GO111MODULE=off go get github.com/hairyhenderson/gomplate/cmd/gomplate
	GO111MODULE=off go get github.com/Songmu/ghch

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

.PHONY: default test
