#!/usr/bin/env bash

set +e

gometalinter --debug --deadline=240s ./...
