#!/usr/bin/env bash

set +e

gometalinter -j2 --vendor --deadline=480s ./... "$@"
