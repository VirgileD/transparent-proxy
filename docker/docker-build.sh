#!/bin/sh
set -e
apk add --update go build-base git ca-certificates iptables
mkdir -p /go/src/go-any-proxy
cp -r /src /go/src/go-any-proxy
cd /go/src/go-any-proxy/src
export GOPATH=/go
timestamp=`date +%s`
cat <<EOF >version.go
package main

const BUILDTIMESTAMP = $timestamp
const BUILDUSER      = "root"
const BUILDHOST      = "docker"
EOF

go get
go build -o /bin/go-any-proxy
apk del go git build-base
cp /src/docker/start-any-proxy.sh /bin
rm -rf /go /var/cache/apk/* /src
