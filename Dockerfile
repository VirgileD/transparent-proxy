FROM golang:alpine AS builder

RUN apk add git

COPY . /go/src/go-any-proxy

WORKDIR /go/src/go-any-proxy

RUN docker/docker-build.sh

LABEL build = "multi-stage"

FROM alpine

LABEL maintainer = "Feng Zhou <feng.zh@gmail.com>"

RUN apk add iptables; rm -rf /var/cache/apk/*

COPY --from=builder /go/src/go-any-proxy/docker/start-any-proxy.sh /go/bin/go-any-proxy /bin/

ENV LISTEN_PORT=3129 HTTP_PROXY="" NO_PROXY="" IPTABLE_MARK="5" PROXY_PORTS="80,443" VERBOSE=false DNS_PORT=0 PROXY_CONFIG_FILE=

CMD ["/bin/start-any-proxy.sh"]
