#!/bin/bash
# Upload source tarball to Launchpad PPA (requires dput and debuild).
set -euo pipefail
VERSION="${1:-0.1.0}"
PPA="${PPA:-digitaldefiance/brightnexus}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
gbp buildpackage -S -us -uc || debuild -S -us -uc
dput "ppa:${PPA}" "../brightnexus_${VERSION}-1_source.changes"
