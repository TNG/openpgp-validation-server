#!/usr/bin/env bash

set +e

STATUS=0
PIDS=""

./enforce_gofmt.sh &
PIDS+="$! "

go test -covermode=atomic ./... &  # Prefer short, human readable output of test results here
PIDS+="$! "

./lint.sh &
PIDS+="$! "

for pid in $PIDS; do
    wait $pid
    if [ $? -ne 0 ]; then
        STATUS=$?
    fi
done

exit $STATUS
