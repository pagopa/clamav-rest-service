#!/bin/env bash
#
# Entrypoint of the ClamAV REST service with bundled clamd.
#

set -e

# redirect daemons output to stderr
clamd_log=/var/log/clamav/clamd.log
freshclam_log=/var/log/clamav/freshclam.log
touch $clamd_log $freshclam_log
tail --pid 1 -n0 -F $clamd_log $freshclam_log > /dev/stderr &

# update antivirus database
freshclam
# start the clamav daemon
clamd

# start supercronic for scheduled freshclam updates. we don't start
# freshclam -d because you can't configure the timing correctly, you
# can just specify how many times a day. we want a real cron here.
echo "${CLAMAV_DB_REFRESH_CRON} /usr/bin/freshclam >> $freshclam_log 2>&1" > /tmp/freshclam-cron
supercronic /tmp/freshclam-cron &

exec "$@"

