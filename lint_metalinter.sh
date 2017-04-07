#!/usr/bin/env bash

set +e

gometalinter --vendor --deadline=480s ./... "$@"
