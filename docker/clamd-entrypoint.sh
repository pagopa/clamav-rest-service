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

# handle test mode vs production database
if [ "$CLAMAV_TEST_MODE" = "true" ]; then
    # create minimal eicar-only database.  this will greatly reduce
    # memory usage in testing environments but will just recognize the
    # EICAR test file as virus
    echo "44d88612fea8a8f36de82e1278abb02f:68:EICAR-Test-Signature" > /var/lib/clamav/test.hdb
    echo "WARNING: Running in TEST MODE. Minimal signatures loaded, DO NOT USE IN PRODUCTION"
else
    # update antivirus database
    freshclam

    # start supercronic for scheduled freshclam updates. we don't start
    # freshclam -d because you can't configure the timing correctly, you
    # can just specify how many times a day. we want a real cron here.
    echo "${CLAMAV_DB_REFRESH_CRON} /usr/bin/freshclam >> $freshclam_log 2>&1" > /tmp/freshclam-cron
    supercronic /tmp/freshclam-cron &
fi

# start the clamav daemon
clamd

exec "$@"
