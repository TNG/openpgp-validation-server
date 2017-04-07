#!/usr/bin/env bash

set +e

gometalinter --deadline=480s ./... "$@"
