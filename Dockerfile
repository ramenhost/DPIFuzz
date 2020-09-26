FROM golang:1.14-alpine
RUN apk add --no-cache make cmake vim gcc g++ git openssl openssl-dev perl-test-harness-utils tcpdump libpcap libpcap-dev libbsd-dev perl-scope-guard perl-test-tcp python3 


RUN mkdir -p /go/src/github.com/QUIC-Tracker/quic-tracker
ADD . /go/src/github.com/QUIC-Tracker/quic-tracker 
WORKDIR /go/src/github.com/QUIC-Tracker/quic-tracker
ENV GOPATH /go
RUN go get -v || true
WORKDIR /go/src/github.com/mpiraux/pigotls
RUN make
WORKDIR /go/src/github.com/mpiraux/ls-qpack-go
RUN make
WORKDIR /go/src/github.com/QUIC-Tracker/quic-tracker