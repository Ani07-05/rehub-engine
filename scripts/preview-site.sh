#!/bin/sh
# Serves the landing page locally with the installer copied next to it, like the Vercel build does.
set -eu
cd "$(dirname "$0")/.."
cp scripts/install.sh site/install.sh
port=${1:-18100}
echo "Landing page: http://localhost:$port/"
exec python3 -m http.server "$port" --bind 127.0.0.1 --directory site
