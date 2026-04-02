#!/bin/sh
set -e

# Docker named volumes mount as root:root on first creation, even if the
# image directory was chowned during build. Fix ownership at runtime before
# dropping privileges so the app can write its database and logs.
chown -R netbot:netbot /app/data /app/logs /app/reports /app/nuclei-templates 2>/dev/null || true

# Drop from root to the netbot user and exec the application.
exec gosu netbot "$@"
