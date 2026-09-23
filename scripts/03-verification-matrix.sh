#!/usr/bin/env bash
# ==============================================================================
# Script: 03-verification-matrix.sh
# Purpose: Phase 2 Full Verification Matrix across Scenarios A, B, C, D
# ==============================================================================

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
KEYS_DIR="${POC_ROOT}/keys"
WORK_DIR="${POC_ROOT}/work"
OLD_REPO="${WORK_DIR}/old-repo"
RESULTS_DIR="${POC_ROOT}/results"

mkdir -p "${RESULTS_DIR}" "${WORK_DIR}"

# Locate gittuf binary
GITTUF_BIN="${GITTUF:-$(command -v gittuf 2>/dev/null || true)}"
if [ -z "${GITTUF_BIN}" ]; then
    CURRENT_USER="${USER:-${USERNAME:-}}"
    for candidate in \
        "${HOME}/go/bin/gittuf" \
        "${HOME}/go/bin/gittuf.exe" \
        "/c/Users/${CURRENT_USER}/go/bin/gittuf.exe" \
        "/mnt/c/Users/${CURRENT_USER}/go/bin/gittuf.exe" \
        "${POC_ROOT}/bin/gittuf" \
        "${POC_ROOT}/bin/gittuf.exe" \
        "${POC_ROOT}/../gittuf.exe"; do
        if [ -n "${candidate}" ] && [ -f "${candidate}" ]; then
            GITTUF_BIN="${candidate}"
            break
        fi
    done
fi
if [ -z "${GITTUF_BIN}" ]; then
    echo "gittuf not found; set GITTUF=/path/to/gittuf" >&2
    exit 2
fi

echo "======================================================================"
echo " PHASE 2: VERIFICATION MATRIX EXECUTION"
echo " Date: $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
echo "======================================================================"
echo

# ------------------------------------------------------------------------------
# SCENARIO A: BASELINE SHA-1 REPOSITORY
# ------------------------------------------------------------------------------
LOG_A="${RESULTS_DIR}/03-matrix-scenario-a.txt"
echo "=== Running Scenario A (Baseline SHA-1 Repo) ==="

(
    cd "${OLD_REPO}"
    echo "=== Scenario A: Baseline SHA-1 Repo ==="
    echo "[CMD] gittuf verify-ref --verbose main in work/old-repo"
    "${GITTUF_BIN}" verify-ref --verbose main
    EXIT_CODE=$?
    echo "EXIT: ${EXIT_CODE}"
    exit ${EXIT_CODE}
) > "${LOG_A}" 2>&1
EXIT_A=$?
echo "Scenario A Finished: Exit ${EXIT_A}"
echo

# ------------------------------------------------------------------------------
# SCENARIO B: NAIVE COPY TO SHA-256 REPOSITORY
# ------------------------------------------------------------------------------
LOG_B="${RESULTS_DIR}/03-matrix-scenario-b.txt"
echo "=== Running Scenario B (Naive Copy to SHA-256 Repo) ==="

NAIVE_REPO="${WORK_DIR}/new-repo-naive"
rm -rf "${NAIVE_REPO}"
mkdir -p "${NAIVE_REPO}"

(
    cd "${NAIVE_REPO}"
    echo "=== Scenario B: Naive Copy to SHA-256 Repo ==="
    echo "[CMD] git init --object-format=sha256 -b main"
    git init --object-format=sha256 -b main
    git config user.name "Developer User"
    git config user.email "dev@example.com"

    echo "[CMD] fast-export from old-repo | fast-import into new-repo-naive"
    (cd "${OLD_REPO}" && git fast-export --all --signed-tags=strip) | git fast-import

    # EXPECTED FAILURE (fail-closed layer 1): Git refuses to fetch between a
    # SHA-1 and a SHA-256 repository. The refs/gittuf/* history is present in
    # this repo anyway, because `fast-export --all` above already re-imported
    # it: the RSL commits get new SHA-256 IDs, but the target IDs written in
    # their messages stay 40-char SHA-1. That is what verify-ref trips on
    # below (fail-closed layer 2).
    echo "[CMD] Fetching refs/gittuf/* from old-repo (naive copy, EXPECTED to fail)"
    git fetch "${OLD_REPO}" "refs/gittuf/*:refs/gittuf/*"
    echo "FETCH EXIT: $? (expected non-zero: cross-algorithm fetch is refused)"

    echo "[CMD] refs/gittuf/* present after fast-import (SHA-256 IDs):"
    git for-each-ref refs/gittuf/

    echo "[CMD] Checking repo object format and head"
    git rev-parse --show-object-format
    git rev-parse HEAD

    echo "[CMD] Running gittuf verify-ref --verbose main in work/new-repo-naive"
    "${GITTUF_BIN}" verify-ref --verbose main
    EXIT_CODE=$?
    echo "EXIT: ${EXIT_CODE}"
    exit ${EXIT_CODE}
) > "${LOG_B}" 2>&1
EXIT_B=$?
echo "Scenario B Finished: Exit ${EXIT_B}"
echo

# ------------------------------------------------------------------------------
# SCENARIO C: FRESH CHAIN IN SHA-256 REPOSITORY
# ------------------------------------------------------------------------------
LOG_C="${RESULTS_DIR}/03-matrix-scenario-c.txt"
echo "=== Running Scenario C (Fresh Chain in SHA-256 Repo) ==="

FRESH_REPO="${WORK_DIR}/new-repo-fresh"
rm -rf "${FRESH_REPO}"
mkdir -p "${FRESH_REPO}"

(
    cd "${FRESH_REPO}"
    echo "=== Scenario C: Fresh Chain in SHA-256 Repo ==="
    echo "[CMD] git init --object-format=sha256 -b main"
    git init --object-format=sha256 -b main
    git config user.name "Developer User"
    git config user.email "dev@example.com"
    git config gpg.format ssh
    git config user.signingkey "${KEYS_DIR}/dev.pub"

    echo "[CMD] fast-export from old-repo | fast-import into new-repo-fresh"
    (cd "${OLD_REPO}" && git fast-export --all --signed-tags=strip) | git fast-import

    echo "[CMD] Stripping historical refs/gittuf/* to prepare for fresh init"
    git for-each-ref --format="%(refname)" refs/gittuf/ | while read ref; do git update-ref -d "$ref"; done || true

    echo "[CMD] Initializing fresh gittuf trust & policy in new-repo-fresh"
    "${GITTUF_BIN}" trust init -k "${KEYS_DIR}/root" --create-rsl-entry
    "${GITTUF_BIN}" trust add-policy-key -k "${KEYS_DIR}/root" --policy-key "${KEYS_DIR}/policy.pub" --create-rsl-entry
    "${GITTUF_BIN}" policy init -k "${KEYS_DIR}/policy" --create-rsl-entry
    "${GITTUF_BIN}" policy add-key -k "${KEYS_DIR}/policy" --public-key "${KEYS_DIR}/dev.pub" --create-rsl-entry

    DEV_KEY_ID="$("${GITTUF_BIN}" policy list-principals --policy-ref policy-staging 2>/dev/null | grep -o 'SHA256:[^ :]*' | head -n1 || true)"
    "${GITTUF_BIN}" policy add-rule -k "${KEYS_DIR}/policy" --rule-name protect-main --rule-pattern "refs/heads/main" --authorize "${DEV_KEY_ID}" --create-rsl-entry
    "${GITTUF_BIN}" policy apply -k "${KEYS_DIR}/policy" --local-only

    echo "[CMD] Recording main ref in fresh RSL log"
    "${GITTUF_BIN}" rsl record main --local-only

    echo "[CMD] Running gittuf verify-ref --verbose main in work/new-repo-fresh"
    "${GITTUF_BIN}" verify-ref --verbose main
    EXIT_CODE=$?
    echo "EXIT: ${EXIT_CODE}"
    exit ${EXIT_CODE}
) > "${LOG_C}" 2>&1
EXIT_C=$?
echo "Scenario C Finished: Exit ${EXIT_C}"
echo

# ------------------------------------------------------------------------------
# SCENARIO D: FRESH CHAIN + GENESIS BRIDGE ATTESTATION
# ------------------------------------------------------------------------------
LOG_D="${RESULTS_DIR}/03-matrix-scenario-d.txt"
echo "=== Running Scenario D (Fresh Chain + Genesis Bridge) ==="

ATTEST_REPO="${WORK_DIR}/new-repo-attest"
rm -rf "${ATTEST_REPO}"
mkdir -p "${ATTEST_REPO}"

(
    cd "${ATTEST_REPO}"
    echo "=== Scenario D: Fresh Chain + Genesis Bridge ==="
    echo "[CMD] git init --object-format=sha256 -b main"
    git init --object-format=sha256 -b main
    git config user.name "Developer User"
    git config user.email "dev@example.com"
    git config gpg.format ssh
    git config user.signingkey "${KEYS_DIR}/dev.pub"

    echo "[CMD] fast-export from old-repo | fast-import into new-repo-attest"
    (cd "${OLD_REPO}" && git fast-export --all --signed-tags=strip) | git fast-import

    echo "[CMD] Stripping historical refs/gittuf/* to prepare for fresh bridge init"
    git for-each-ref --format="%(refname)" refs/gittuf/ | while read ref; do git update-ref -d "$ref"; done || true

    OLD_RSL_TIP="$(cd "${OLD_REPO}" && git rev-parse refs/gittuf/reference-state-log)"
    COMMITMENT_SHA256="$(grep 'commitment_sha256' "${POC_ROOT}/archives/snapshot-manifest.json" | awk -F'"' '{print $4}')"
    OLD_ROOT_KEY_FINGERPRINT="$(ssh-keygen -l -f "${KEYS_DIR}/root.pub" | awk '{print $2}')"

    echo "Genesis Bridge Data:"
    echo "  old_rsl_tip:               ${OLD_RSL_TIP}"
    echo "  commitment_sha256:         ${COMMITMENT_SHA256}"
    echo "  old_root_key_fingerprint:  ${OLD_ROOT_KEY_FINGERPRINT}"

    cat <<EOF > genesis-bridge.json
{
  "type": "https://gittuf.dev/genesis-bridge/v0.1",
  "old_rsl_tip": "${OLD_RSL_TIP}",
  "commitment_sha256": "${COMMITMENT_SHA256}",
  "old_root_key_fingerprint": "${OLD_ROOT_KEY_FINGERPRINT}",
  "created_at": "$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
}
EOF

    echo "[CMD] Signing Genesis Bridge payload with OLD root key"
    ssh-keygen -Y sign -f "${KEYS_DIR}/root" -n file genesis-bridge.json

    echo "[CMD] Initializing fresh gittuf trust & policy in new-repo-attest"
    "${GITTUF_BIN}" trust init -k "${KEYS_DIR}/root" --create-rsl-entry
    "${GITTUF_BIN}" trust add-policy-key -k "${KEYS_DIR}/root" --policy-key "${KEYS_DIR}/policy.pub" --create-rsl-entry
    "${GITTUF_BIN}" policy init -k "${KEYS_DIR}/policy" --create-rsl-entry
    "${GITTUF_BIN}" policy add-key -k "${KEYS_DIR}/policy" --public-key "${KEYS_DIR}/dev.pub" --create-rsl-entry

    DEV_KEY_ID="$("${GITTUF_BIN}" policy list-principals --policy-ref policy-staging 2>/dev/null | grep -o 'SHA256:[^ :]*' | head -n1 || true)"
    "${GITTUF_BIN}" policy add-rule -k "${KEYS_DIR}/policy" --rule-name protect-main --rule-pattern "refs/heads/main" --authorize "${DEV_KEY_ID}" --create-rsl-entry
    "${GITTUF_BIN}" policy apply -k "${KEYS_DIR}/policy" --local-only

    "${GITTUF_BIN}" rsl record main --local-only

    # Embed the bridge as a tree entry inside refs/gittuf/attestations
    # (hash-migration/genesis-bridge.json[.sig]). A separate ref such as
    # refs/gittuf/attestations/genesis cannot coexist with
    # refs/gittuf/attestations, and gittuf's attestation loader skips tree
    # entries it does not know. --no-filters keeps the blobs byte-identical
    # to what was signed.
    echo "[CMD] Committing Genesis Bridge into refs/gittuf/attestations"
    BLOB_P="$(git hash-object -w --no-filters genesis-bridge.json)"
    BLOB_S="$(git hash-object -w --no-filters genesis-bridge.json.sig)"
    SUB_TREE="$(printf '100644 blob %s\tgenesis-bridge.json\n100644 blob %s\tgenesis-bridge.json.sig\n' "${BLOB_P}" "${BLOB_S}" | git mktree)"
    PARENT_ARGS=()
    if git rev-parse -q --verify refs/gittuf/attestations >/dev/null; then
        PARENT_ARGS=(-p "$(git rev-parse refs/gittuf/attestations)")
        EXISTING_ENTRIES="$(git ls-tree refs/gittuf/attestations | grep -v "	hash-migration$" || true)"
    else
        EXISTING_ENTRIES=""
    fi
    TOP_TREE="$( { [ -n "${EXISTING_ENTRIES}" ] && echo "${EXISTING_ENTRIES}"; printf '040000 tree %s\thash-migration\n' "${SUB_TREE}"; } | git mktree)"
    ATTEST_COMMIT="$(git commit-tree "${TOP_TREE}" "${PARENT_ARGS[@]}" -m "Add hash-migration genesis bridge (old RSL tip ${OLD_RSL_TIP})")"
    git update-ref refs/gittuf/attestations "${ATTEST_COMMIT}"
    echo "refs/gittuf/attestations -> ${ATTEST_COMMIT}"
    "${GITTUF_BIN}" rsl record refs/gittuf/attestations --local-only

    # From here on, only the copy inside the ref is used.
    rm -f genesis-bridge.json genesis-bridge.json.sig
    echo "root-key $(cat "${KEYS_DIR}/root.pub")" > allowed_signers
    git cat-file blob "${ATTEST_COMMIT}:hash-migration/genesis-bridge.json" > ref-bridge.json
    git cat-file blob "${ATTEST_COMMIT}:hash-migration/genesis-bridge.json.sig" > ref-bridge.json.sig

    FAILED=0
    check() {  # check <id> <expected: pass|fail> <cmd...>
        local id="$1" want="$2"; shift 2
        echo "[CMD] ${id}: $*"
        "$@"
        local rc=$?
        echo "${id} EXIT: ${rc}"
        if { [ "${want}" = pass ] && [ ${rc} -eq 0 ]; } || { [ "${want}" = fail ] && [ ${rc} -ne 0 ]; }; then
            echo "${id}: OK (expected ${want})"
        else
            echo "${id}: UNEXPECTED (expected ${want})"; FAILED=1
        fi
    }

    check D1 pass git cat-file -p refs/gittuf/attestations:hash-migration/genesis-bridge.json
    check D2 pass sh -c 'ssh-keygen -Y verify -f allowed_signers -I root-key -n file -s ref-bridge.json.sig < ref-bridge.json'
    sed 's/"old_rsl_tip": "./"old_rsl_tip": "X/' ref-bridge.json > ref-bridge-tampered.json
    check D3 fail sh -c 'ssh-keygen -Y verify -f allowed_signers -I root-key -n file -s ref-bridge.json.sig < ref-bridge-tampered.json'
    check D4 pass sh -c "'${GITTUF_BIN}' rsl log | grep -A2 'Ref:    refs/gittuf/attestations'"
    check D5 pass "${GITTUF_BIN}" verify-ref --verbose main

    echo "NOTE: D2/D3 are verified with ssh-keygen, not gittuf. gittuf verify-ref"
    echo "      does not read hash-migration/*; D5 only shows gittuf tolerates it."
    echo "EXIT: ${FAILED}"
    exit ${FAILED}
) > "${LOG_D}" 2>&1
EXIT_D=$?
echo "Scenario D Finished: Exit ${EXIT_D}"
echo

# Summary Matrix output
echo "======================================================================"
echo " VERIFICATION MATRIX SUMMARY"
echo "======================================================================"
echo "Scenario A (Baseline):       Exit ${EXIT_A}"
echo "Scenario B (Naive Copy):     Exit ${EXIT_B}"
echo "Scenario C (Fresh Chain):    Exit ${EXIT_C}"
echo "Scenario D (Genesis Bridge): Exit ${EXIT_D}"
echo "======================================================================"