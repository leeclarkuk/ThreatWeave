#!/usr/bin/env bash
# Reproducibility check. Clones the COMMITTED tree into an empty directory and proves it installs, builds, passes its
# tests, runs with production dependencies only, and does not modify tracked files while doing so.
# Needs network access to the npm registry. Usage: npm run verify
set -euo pipefail
src="$(git rev-parse --show-toplevel)"
dirty="$(git -C "$src" status --porcelain | wc -l | tr -d ' ')"
if [ "$dirty" != "0" ]; then echo "NOTE: $dirty uncommitted change(s) in the working tree. This verifies the last COMMIT only; they are not covered."; fi
tmp="$(mktemp -d)"; trap 'kill "${pid:-0}" 2>/dev/null || true; rm -rf "$tmp"' EXIT
step() { printf '\n== %s\n' "$*"; }

step "clone committed tree (no node_modules, no build output)"
git clone --quiet "$src" "$tmp/repo"; cd "$tmp/repo"
git rev-parse --short HEAD
test ! -e node_modules && test ! -e packages/core/dist

step "node $(node -v) against engines $(node -p "require('./package.json').engines.node"); .nvmrc=$(cat .nvmrc)"
node -e "const [a,b]=process.versions.node.split('.').map(Number); if (a<20||(a===20&&b<3)) { console.error('Node too old'); process.exit(1); }"

step "npm ci (fails if package-lock.json and package.json disagree)"
npm ci --no-audit --no-fund 2>&1 | tail -2

step "build, unit tests, simulated evaluation, example validation"
npm run check 2>&1 | grep -E "Test Files|Tests |TOTAL|^OK|error" 

step "tracked files unchanged by build and tests"
if [ -n "$(git status --porcelain)" ]; then echo "FAIL: build or tests modified tracked files:"; git status --porcelain; exit 1; fi
echo "clean"

step "production-only runtime (npm ci --omit=dev + build output only)"
rt="$tmp/runtime"; mkdir -p "$rt"
cp package.json package-lock.json tsconfig.base.json .npmrc "$rt/"
for p in core ai server cli web; do mkdir -p "$rt/packages/$p"; cp "packages/$p/package.json" "$rt/packages/$p/"; done
(cd "$rt" && npm ci --omit=dev --no-audit --no-fund 2>&1 | tail -1)
for p in core ai server cli; do cp -r "packages/$p/dist" "$rt/packages/$p/dist"; done
cp -r packages/web/dist "$rt/packages/web/dist"; cp -r examples "$rt/examples"
cd "$rt"
port=$((20000 + RANDOM % 20000))
THREATWEAVE_DATA="$rt/data" THREATWEAVE_EXAMPLES="$rt/examples" THREATWEAVE_WEB_DIR="$rt/packages/web/dist" node packages/cli/dist/bin.js serve --port "$port" >"$rt/serve.log" 2>&1 & pid=$!
for i in $(seq 1 40); do curl -sf "localhost:$port/api/health" >/dev/null && break; sleep 0.25; done
curl -sf "localhost:$port/api/health"; echo
test "$(curl -s -o /dev/null -w '%{http_code}' "localhost:$port/")" = "200"
curl -sf -X POST -H 'content-type: application/json' -H 'x-threatweave: 1' -d '{"example":"northwind"}' "localhost:$port/api/projects" | head -c 80; echo
node packages/cli/dist/bin.js validate examples/northwind.threatweave.json

printf '\nALL CHECKS PASSED for commit %s\n' "$(git -C "$tmp/repo" rev-parse --short HEAD)"
