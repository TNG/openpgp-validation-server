#!/usr/bin/env bash

set +e

gometalinter --deadline=240s ./... "$@"
