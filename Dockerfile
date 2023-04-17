FROM golang:1.20-alpine3.17 AS builder

WORKDIR /prox-them-all
COPY go.mod go.sum ./
RUN go mod download

COPY *.go *.json ./
RUN go build

FROM alpine:3.17

LABEL maintainer = "Feng Zhou <feng.zh@gmail.com>"

RUN apk add iptables; rm -rf /var/cache/apk/*

COPY --from=builder /prox-them-all/prox-them-all /prox-them-all/config.json /bin/

CMD ["/bin/prox-them-all", "-c", "/bin/config.json" ]
