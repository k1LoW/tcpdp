PKG = github.com/k1LoW/tcpdp
COMMIT = $$(git describe --tags --always)
OSNAME=${shell uname -s}
ifeq ($(OSNAME),Darwin)
	export LO = lo0
	export MYSQL_DISABLE_SSL = --ssl-mode=DISABLED
  export GOMPLATE_OS=darwin
else
	export LO = lo
	export MYSQL_DISABLE_SSL = --skip-ssl
	export GOMPLATE_OS=linux
endif

export GO111MODULE=on

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
ci: depsdev test_race test_with_integration sec

test:
	go test -v $(shell go list ./... | grep -v misc) -coverprofile=coverage.txt -covermode=count

sec:
	gosec ./...

test_race:
	go test $(shell go list ./... | grep -v misc) -race

test_with_integration: build
	go test -v $(shell go list ./... | grep -v misc) -tags integration -coverprofile=coverage.txt -covermode=count

build:
	go build -ldflags="$(BUILD_LDFLAGS)"

install:
	cp tcpdp $(BINDIR)/tcpdp

build_darwin: depsdev
	$(eval ver = v$(shell gobump show -r version/))
	$(eval pkg = tcpdp_v$(shell gobump show -r version/)_darwin_amd64)
	go build -ldflags="$(RELEASE_BUILD_LDFLAGS) -X $(PKG).version=$(ver)"
	[ -d ./dist/$(ver) ] || mkdir -p ./dist/$(ver)
	mkdir $(pkg)
	mv tcpdp ./$(pkg)/tcpdp
	cp CHANGELOG.md README.md LICENSE ./$(pkg)
	tar -zcvf ./dist/$(ver)/$(pkg).tar.gz --exclude='*/.*' ./$(pkg)
	rm -rf ./$(pkg)

build_in_docker:
	$(eval ver = v$(shell gobump show -r version/))
	$(eval pkg = tcpdp_v$(shell gobump show -r version/)_linux_amd64.$(DIST))
	go build -ldflags="$(RELEASE_BUILD_LDFLAGS) -X $(PKG).version=$(ver)"
	[ -d ./dist/$(ver) ] || mkdir -p ./dist/$(ver)
	mkdir $(pkg)
	mv tcpdp ./$(pkg)/tcpdp
	cp CHANGELOG.md README.md LICENSE ./$(pkg)
	tar -zcvf ./dist/$(ver)/$(pkg).tar.gz ./$(pkg)
	rm -rf ./$(pkg)

build_static_in_docker:
	$(eval ver = v$(shell gobump show -r version/))
	$(eval pkg = tcpdp_v$(shell gobump show -r version/)_linux_amd64_static.$(DIST))
	cd /usr/local/src/libpcap-$(LIBPCAP_VERSION) && ./configure && make && make install
	go build -a -tags netgo -installsuffix netgo -ldflags="$(RELEASE_BUILD_LDFLAGS) -X $(PKG).version=$(ver) -X $(PKG).libpcap=$(LIBPCAP_VERSION) -linkmode external -extldflags -static"
	[ -d ./dist/$(ver) ] || mkdir -p ./dist/$(ver)
	mkdir $(pkg)
	mv tcpdp ./$(pkg)/tcpdp
	cp CHANGELOG.md README.md LICENSE ./$(pkg)
	tar -zcvf ./dist/$(ver)/$(pkg).tar.gz ./$(pkg)
	rm -rf ./$(pkg)

build_rpm:
	$(eval ver = v$(shell gobump show -r version/))
	$(eval no_v_ver = $(shell gobump show -r version/))
	$(eval pkg = tcpdp-$(shell gobump show -r version/))
	go build -ldflags="$(RELEASE_BUILD_LDFLAGS) -X $(PKG).version=$(ver)"
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
	go build -ldflags="$(RELEASE_BUILD_LDFLAGS) -X $(PKG).version=$(ver)"
	mkdir -p $(workdir)/DEBIAN $(workdir)/usr/bin
	cat ./template/control.template | VERSION=$(no_v_ver) gomplate > $(workdir)/DEBIAN/control
	mv tcpdp $(workdir)/usr/bin
	fakeroot dpkg-deb --build $(workdir) /go/src/github.com/k1LoW/tcpdp/dist/$(ver)
	rm -rf $(workdir)

depsdev:
	go get golang.org/x/tools/cmd/cover
	go get golang.org/x/lint/golint
	go get github.com/motemen/gobump/cmd/gobump
	go get github.com/tcnksm/ghr
	curl -o $(GOPATH)/bin/gomplate -sSL https://github.com/hairyhenderson/gomplate/releases/download/v3.4.1/gomplate_$(GOMPLATE_OS)-amd64
	chmod 755 $(GOPATH)/bin/gomplate
	go get github.com/Songmu/ghch
	go get github.com/securego/gosec/cmd/gosec

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
