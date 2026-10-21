#!/bin/sh
# Deploys site/ to Vercel production as a static site, with the current installer next to it.
# Needs the vercel CLI logged in (vercel login). Uploads only the site files, not the repository.
set -eu
cd "$(dirname "$0")/.."
command -v vercel >/dev/null 2>&1 || { echo "deploy-site: install the vercel CLI first (npm i -g vercel)" >&2; exit 1; }
project=${REHUB_VERCEL_PROJECT:-rehub-engine}
tmp=$(mktemp -d)/site
trap 'rm -rf "$(dirname "$tmp")"' EXIT
mkdir -p "$tmp"
cp -R site/. "$tmp/"
cp scripts/install.sh "$tmp/install.sh"
python3 - "$tmp/vercel.json" <<'PY'
import json, sys
cfg = json.load(open("vercel.json"))
cfg.pop("buildCommand", None)
cfg.pop("outputDirectory", None)
json.dump(cfg, open(sys.argv[1], "w"), indent=2)
PY
cd "$tmp"
vercel link --yes --project "$project" >/dev/null
rm -f .env.local
vercel deploy --prod --yes 2>&1 | tail -3
echo "Live: https://$project.vercel.app"
