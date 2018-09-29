FROM golang:latest
RUN apt-get -qq update && \
    apt-get install -qq libpcap-dev \
    build-essential \
    vim
ADD . /go/src/github.com/k1LoW/tcpdp
WORKDIR /go/src/github.com/k1LoW/tcpdp
