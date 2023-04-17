#!/bin/bash

set -e
timestamp=`date --rfc-3339='second'`

if [ ! -f "./version.go" ]
then
    pwd
    echo "Please execute in project root directory"
    exit 1
fi


echo -n "Enter semver: "
read -r semver
if [[ ! $semver =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]
then
    echo "Something is wrong with your version"
    exit 1
fi

echo "Generating version file..."
cat <<EOF >version.go
package main

const VERSION = "$semver"
const BUILDTIMESTAMP = "$timestamp"
const BUILDUSER      = "root"
const BUILDHOST      = "docker"
EOF

echo "Building prox-them-all docker image..."
docker build -t prox-them-all .

