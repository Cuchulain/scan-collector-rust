#!/bin/sh
set -eu

# A bind mount hides the ownership set in the image. Give the app user access
# to its dedicated data directory before dropping privileges.
chown -R app:app /data
exec su-exec app "$@"
