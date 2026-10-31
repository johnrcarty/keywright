#!/usr/bin/env bash
# Uses only a Compose file in a temporary directory. No source tree or local build.
set -euo pipefail
IMAGE="${1:?usage: smoke-image.sh IMAGE EXPECTED_VERSION [always|never]}"
VERSION="${2:?set expected version}"
PULL="${3:-always}"
case "$PULL" in always|never) ;; *) echo "invalid pull policy" >&2; exit 2 ;; esac
SOURCE_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SMOKE_DIR="$(mktemp -d)"
PROJECT="kw-smoke-${RANDOM}-$$"
cp "${4:-$SOURCE_ROOT/deploy/compose.yaml}" "$SMOKE_DIR/compose.yaml"
export KEYWRIGHT_IMAGE="$IMAGE" KW_BIND_ADDRESS=127.0.0.1 KW_HTTP_PORT=0
export KW_PUBLIC_URL=http://localhost:8700 KW_TRUSTED_PROXIES=
compose() { docker compose --project-name "$PROJECT" --file "$SMOKE_DIR/compose.yaml" "$@"; }
cleanup() {
  code=$?
  if [ "$code" -ne 0 ]; then compose logs --no-color || true; fi
  compose down --volumes --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$SMOKE_DIR"
  exit "$code"
}
trap cleanup EXIT
cd "$SMOKE_DIR"
compose config --format json | python3 -c 'import json,sys; d=json.load(sys.stdin); assert "build" not in d["services"]["keywright"]; assert d["services"]["keywright"]["image"] == sys.argv[1]' "$IMAGE"
compose up -d --no-build --pull "$PULL" --wait --wait-timeout 120
compose exec -T keywright python - "$VERSION" <<'PYCHECK'
import json, sys, urllib.request
from pathlib import Path
import asyncpg
from keywright_server.mcp_server import build_server
expected = sys.argv[1]
health = json.load(urllib.request.urlopen("http://127.0.0.1:8700/healthz", timeout=5))
assert health["ok"] and health["version"] == expected, health
with urllib.request.urlopen("http://127.0.0.1:8700/ui", timeout=5) as response:
    assert response.status == 200 and response.url.endswith("/ui/setup"), response.url
    assert b"password" in response.read().lower()
assert build_server().version == expected
assert Path("/data/keywright.db").is_file()
Path("/data/smoke-marker").write_text(expected)
print("Fresh health, setup, MCP version, database and optional driver verified")
PYCHECK
compose up -d --no-build --pull never --force-recreate --wait --wait-timeout 120
compose exec -T keywright python - "$VERSION" <<'PYPERSIST'
import json, sys, urllib.request
from pathlib import Path
assert Path("/data/smoke-marker").read_text() == sys.argv[1]
health = json.load(urllib.request.urlopen("http://127.0.0.1:8700/healthz", timeout=5))
assert health["ok"] and health["version"] == sys.argv[1]
assert Path("/data/keywright.db").is_file()
print("Data volume persists across container replacement")
PYPERSIST
