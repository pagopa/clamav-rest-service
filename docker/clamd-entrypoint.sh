#!/bin/env bash

set -e

# redirect daemons output to stderr
tail --pid 1 -n0 -F /var/log/clamav/clamd.log /var/log/clamav/clamd.log > /dev/stderr &

# update antivirus database
freshclam
# start the clamav daemon
clamd
# start the freshclam daemon to keep automated updates
freshclam -d

exec "$@"
