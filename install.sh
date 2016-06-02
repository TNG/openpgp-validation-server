#!/usr/bin/env bash

set -e

go get -u github.com/alecthomas/gometalinter
gometalinter --install --update

go get -t -v ./...
