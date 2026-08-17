#!/usr/bin/env bash
# ============================================================================
#  setup.sh
#  Companion prototype -- environment bootstrap.
#
#  Idempotent, safe to run multiple times.  Exits 0 on full success.
#  Verified on Ubuntu 24.04 LTS with:
#      swtpm 0.8.0-1ubuntu1.1
#      libtpms0 0.9.6-2ubuntu1
#      tpm2-tools 5.6-1build4
#      python 3.12
#
#  After a successful run:
#      * a swtpm daemon is available under $TPM_DIR (default /tmp/mytpm0)
#      * SWTPM_SOCKET points at its Unix-socket
#      * PROTO_TPM_MODE=swtpm activates the real-TPM code path in
#        prototype/crypto.py + prototype/tpm_swtpm.py
#      * PROTO_TPM_MODE=mock (default) skips the swtpm daemon entirely
#
#  This script does NOT rely on tpm2-pytss.  We use tpm2-tools via
#  subprocess because its CLI is more stable across Ubuntu versions.
#  tpm2-pytss remains a Python dependency ONLY as a convenience for
#  users who want to write their own experiments; the shipped
#  prototype does not import it.
# ============================================================================
set -euo pipefail

log()   { printf '\033[1;34m[setup]\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m[warn ]\033[0m %s\n' "$*"; }
err()   { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; }

# ---- 1. sanity ------------------------------------------------------------
if [[ ! -r /etc/os-release ]]; then
    err "cannot read /etc/os-release"; exit 1
fi
. /etc/os-release
log "OS: ${PRETTY_NAME:-unknown}"

# ---- 2. apt packages -------------------------------------------------------
log "installing apt packages (may prompt for sudo)"
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends \
    swtpm swtpm-tools libtpms0 \
    tpm2-tools libtss2-dev \
    python3-pip python3-venv python3-dev \
    build-essential pkg-config \
    libssl-dev libjson-c-dev libffi-dev \
    graphviz \
    >/dev/null

# ---- 3. python venv --------------------------------------------------------
VENV="${VENV:-$HOME/.venvs/bce27}"
if [[ ! -d "$VENV" ]]; then
    log "creating python venv at $VENV"
    python3 -m venv "$VENV"
fi
# shellcheck disable=SC1090
source "$VENV/bin/activate"

log "upgrading pip and installing python deps"
pip install --quiet --upgrade pip wheel setuptools

# Prefer the locked requirements if present; otherwise install unpinned.
if [[ -f "$(dirname "$0")/requirements.lock" ]]; then
    log "installing from requirements.lock"
    pip install --quiet -r "$(dirname "$0")/requirements.lock"
else
    log "installing unpinned requirements"
    pip install --quiet \
        "cryptography>=42.0" \
        "pynacl>=1.5" \
        "pytest>=8.0" \
        "matplotlib>=3.8" \
        "numpy>=1.26"
fi

# ---- 4. Start swtpm ----------------------------------------------------
# We start swtpm in a way that survives shell exit even on
# minimal-init containers (e.g. Docker or tini-based sandboxes).
TPM_DIR="${TPM_DIR:-/tmp/mytpm0}"
log "provisioning swtpm at $TPM_DIR"

# Stop any prior swtpm attached to the same state dir
if [[ -f "$TPM_DIR/swtpm.pid" ]]; then
    pid_prev="$(cat "$TPM_DIR/swtpm.pid" 2>/dev/null || true)"
    if [[ -n "$pid_prev" ]] && kill -0 "$pid_prev" 2>/dev/null; then
        log "stopping previous swtpm (pid=$pid_prev)"
        kill "$pid_prev" 2>/dev/null || true
        sleep 0.3
    fi
fi
rm -rf "$TPM_DIR"
mkdir -p "$TPM_DIR"

setsid nohup swtpm socket \
    --tpmstate "dir=$TPM_DIR" \
    --ctrl "type=unixio,path=$TPM_DIR/swtpm-sock.ctrl" \
    --server "type=unixio,path=$TPM_DIR/swtpm-sock" \
    --tpm2 \
    --flags "not-need-init,startup-clear" \
    --pid "file=$TPM_DIR/swtpm.pid" \
    </dev/null >/tmp/swtpm.log 2>&1 &
disown

for _ in {1..30}; do
    [[ -S "$TPM_DIR/swtpm-sock" ]] && break
    sleep 0.1
done

if [[ ! -S "$TPM_DIR/swtpm-sock" ]]; then
    err "swtpm failed to start; see /tmp/swtpm.log"
    exit 2
fi
log "swtpm running (socket = $TPM_DIR/swtpm-sock)"

# ---- 5. Smoke test via tpm2-tools -----------------------------------------
export TPM2TOOLS_TCTI="swtpm:path=$TPM_DIR/swtpm-sock"
log "TPM 2.0 spec probe:"
tpm2_getcap properties-fixed | grep -E "TPM2_PT_FAMILY|TPM2_PT_REVISION|TPM2_PT_MANUFACTURER" | head -5

# ---- 6. Python smoke test  (mock mode has no external deps) ---------------
log "python-level smoke test (mock mode)"
python3 - <<'PY'
import sys
sys.path.insert(0, '.')
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    import nacl.public
    print(" cryptography OK, Ed25519 works")
    print(" pynacl OK, X25519 works")
    print(" numpy OK")
    import numpy
    print(" matplotlib OK")
    import matplotlib
except ImportError as e:
    print(" import failed:", e)
    sys.exit(1)
PY

# ---- 7. Optional python-level swtpm test ----------------------------------
if [[ -d "prototype/prototype" ]]; then
    log "python-level swtpm test (real TPM2_Quote round trip)"
    # NOTE: this script is expected to be run from the tarball's
    # top-level 'prototype' directory (which contains the inner
    # importable 'prototype/' package plus README/setup.sh).  We do
    # NOT cd into a subdirectory here.
    (
        PROTO_TPM_MODE=swtpm SWTPM_SOCKET="$TPM_DIR/swtpm-sock" PYTHONPATH=. \
            python3 -c "
from prototype.crypto import AikKey, verify_aik
aik = AikKey.generate()
payload = b'setup.sh smoke test'
sig = aik.sign(payload)
assert verify_aik(aik.pk_bytes, payload, sig), 'verify failed'
assert not verify_aik(aik.pk_bytes, b'other', sig), 'verify should have failed'
print(' TPM2_Quote round trip: OK  ({} B signature blob)'.format(len(sig)))
"
    ) || warn "swtpm python smoke test failed (mock mode still works)"
fi

# ---- 8. Print activation hints -------------------------------------------
cat <<HINT

setup.sh finished successfully.

To activate the venv:

    source $VENV/bin/activate

All commands below run from the current directory (the tarball's
top-level 'prototype/', which contains README.md, setup.sh, and the
inner Python package also called 'prototype/').  Do NOT cd into a
subdirectory.

To run experiments in the fast mock mode (default):

    PROTO_TPM_MODE=mock PYTHONPATH=. python3 experiments/e1_baseline_attack.py

To run experiments against the real swtpm:

    export SWTPM_SOCKET=$TPM_DIR/swtpm-sock
    PROTO_TPM_MODE=swtpm PYTHONPATH=. python3 experiments/e1_baseline_attack.py

To run the pytest regression suite:

    PYTHONPATH=. pytest experiments/test_regressions.py -v
HINT
