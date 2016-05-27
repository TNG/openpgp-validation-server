#!/usr/bin/env bash

set +e

status=0
pids=""

./enforce_gofmt.sh &
pids+="$! "

go test -covermode=atomic ./... &  # Prefer short, human readable output of test results here
pids+="$! "

./lint.sh &
pids+="$! "

for pid in $pids; do
    wait $pid
    result=$?
    if [ $result -ne 0 ]; then
        status=$result
    fi
done

exit $status
