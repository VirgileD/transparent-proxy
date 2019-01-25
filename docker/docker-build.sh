#!/bin/sh
set -e
timestamp=`date +%s`
cat <<EOF >version.go
package main

const BUILDTIMESTAMP = $timestamp
const BUILDUSER      = "root"
const BUILDHOST      = "docker"
EOF

GOOS=linux go get
