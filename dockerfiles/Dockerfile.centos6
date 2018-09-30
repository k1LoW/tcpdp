FROM centos:6
LABEL maintainer="k1LoW <k1lowxb@gmail.com>"

ARG GO_VERSION
ARG LIBPCAP_VERSION

RUN yum install -y epel-release rpmdevtools yum-utils make glibc glibc-static gcc byacc flex bison libpcap-devel
RUN curl -s https://setup.ius.io/ | bash
RUN yum -y remove git && yum -y install git2u

ENV FILE go$GO_VERSION.linux-amd64.tar.gz
ENV URL https://storage.googleapis.com/golang/$FILE
ENV LIBPCAP_VERSION $LIBPCAP_VERSION
ENV LIBPCAP_FILE libpcap-$LIBPCAP_VERSION.tar.gz
ENV LIBPCAP_URL https://www.tcpdump.org/release/$LIBPCAP_FILE

ENV GOPATH /go
ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH

RUN set -eux &&\
  yum -y clean all &&\
  curl -OL $URL &&\
	tar -C /usr/local -xzf $FILE &&\
	rm $FILE &&\
  curl -OL $LIBPCAP_URL &&\
	tar -C /usr/local/src -xzf $LIBPCAP_FILE &&\
	rm $LIBPCAP_FILE &&\
  mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH"

ADD . /go/src/github.com/k1LoW/tcpdp
WORKDIR /go/src/github.com/k1LoW/tcpdp
