#!/usr/bin/env bash
# Manual end-to-end check of the GAP-1 bridge fixes using the real gittuf CLI.
# Runs every scenario against the old binary (12329f5, PR #23) and the new
# binary (fix/gap1-bridge-verification) and writes a TSV of results.
set -u

SP="$(cd "$(dirname "$0")" && pwd)"
OLD="${OLD:-$SP/gittuf-old.sh}"   # PR #23 (12329f5) gittuf; see gittuf-old.sh
NEW="${NEW:-$SP/bin/gittuf-new.exe}"  # gittuf built from this branch
W="$SP/manual"
LOG="$SP/manual_log.txt"
RES="$SP/manual_results.tsv"
rm -rf "$W"; mkdir -p "$W"
: > "$LOG"; printf "id\tbinary\tscenario\texpected\tgot_exit\tverdict\tkey_output\n" > "$RES"

log() { echo "$*" | tee -a "$LOG"; }

# check ID BIN_LABEL BIN SCENARIO EXPECT(ok|fail) PATTERN DIR -- cmd...
check() {
  local id="$1" label="$2" bin="$3" scen="$4" expect="$5" pat="$6" dir="$7"; shift 8
  local out rc verdict
  out="$(cd "$dir" && "$@" 2>&1)"; rc=$?
  if [ "$expect" = ok ]; then
    [ $rc -eq 0 ] && verdict=PASS || verdict=FAIL
  else
    if [ $rc -ne 0 ] && { [ -z "$pat" ] || grep -qF -- "$pat" <<<"$out"; }; then verdict=PASS; else verdict=FAIL; fi
  fi
  local key; key="$(grep -E "FAILED|Error|error|✔|✅|⚠|refusing|not |does not" <<<"$out" | tail -2 | tr '\t\n' '  ' | cut -c1-260)"
  [ -z "$key" ] && key="$(tail -1 <<<"$out" | cut -c1-200)"
  printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n" "$id" "$label" "$scen" "$expect" "$rc" "$verdict" "$key" >> "$RES"
  { echo "===== [$id] [$label] $scen (expect $expect) -> rc=$rc $verdict"; echo "\$ $*"; echo "$out"; echo; } >> "$LOG"
}

KEYS="$W/keys"; SRC="$W/repo-sha1"; DST="$W/repo-sha256"; OTHER="$W/repo-sha1-other"
mkdir -p "$KEYS" "$SRC" "$DST" "$OTHER"
for k in root policy dev attacker; do ssh-keygen -q -t ed25519 -N "" -f "$KEYS/$k" -C "$k@check" ; done

setup_repo() { # dir objectformat
  local d="$1" fmt="$2"
  cd "$d"
  git init -q -b main --object-format="$fmt"
  git config user.name "Check Dev"; git config user.email "dev@check"
  git config gpg.format ssh; git config user.signingkey "../keys/dev.pub"; git config commit.gpgsign true
}
gittuf_policy() { # bin
  local g="$1"
  "$g" trust init -k ../keys/root --create-rsl-entry
  "$g" trust add-policy-key -k ../keys/root --policy-key ../keys/policy.pub --create-rsl-entry
  "$g" policy init -k ../keys/policy --create-rsl-entry
  "$g" policy add-key -k ../keys/policy --public-key ../keys/dev.pub --create-rsl-entry
  local id; id="$("$g" policy list-principals --policy-ref policy-staging 2>/dev/null | grep -o 'SHA256:[^ :]*' | head -n1)"
  "$g" policy add-rule -k ../keys/policy --rule-name protect-main --rule-pattern refs/heads/main --authorize "$id" --create-rsl-entry
  "$g" policy apply -k ../keys/policy --local-only
}

log "## Setup (built with NEW binary; repos are shared by both binaries)"
setup_repo "$SRC" sha1 >>"$LOG" 2>&1
echo hello > README.md; git add README.md; git commit -q -m "initial (sha1)"
gittuf_policy "$NEW" >>"$LOG" 2>&1
echo feature > feature.txt; git add feature.txt; git commit -q -m "feature (sha1)"
"$NEW" rsl record main --local-only >>"$LOG" 2>&1
SHA1_HEAD="$(git rev-parse HEAD)"; SHA1_RSL="$(git rev-parse refs/gittuf/reference-state-log)"
check S1 new "$NEW" "SHA-1 repo verifies on its own" ok "" "$SRC" -- "$NEW" verify-ref main

setup_repo "$DST" sha256 >>"$LOG" 2>&1
(cd "$SRC" && git fast-export --signed-commits=strip --signed-tags=strip refs/heads/main) | git fast-import --quiet
git checkout -q main 2>/dev/null || git reset -q --hard main
gittuf_policy "$NEW" >>"$LOG" 2>&1
"$NEW" rsl record main --local-only >>"$LOG" 2>&1
SHA256_HEAD="$(git rev-parse main)"; SHA256_RSL="$(git rev-parse refs/gittuf/reference-state-log)"
# An unrelated commit in the SHA-256 repo (not reachable from main or the RSL)
git checkout -q --orphan unrelated; git rm -rq --cached . ; echo x > x.txt; git add x.txt; git commit -q -m unrelated
UNRELATED="$(git rev-parse HEAD)"; git checkout -q -f main; git branch -q -D unrelated
check S2 new "$NEW" "SHA-256 repo verifies on its own" ok "" "$DST" -- "$NEW" verify-ref main

setup_repo "$OTHER" sha1 >>"$LOG" 2>&1
echo other > o.txt; git add o.txt; git commit -q -m "other"
gittuf_policy "$NEW" >>"$LOG" 2>&1
"$NEW" rsl record main --local-only >>"$LOG" 2>&1

log "SHA1_HEAD=$SHA1_HEAD SHA1_RSL=$SHA1_RSL"
log "SHA256_HEAD=$SHA256_HEAD SHA256_RSL=$SHA256_RSL UNRELATED=$UNRELATED"

B="$W/bridges"; mkdir -p "$B"
mk() { # bin out key sha1rsl sha1head sha256rsl sha256head
  local g="$1" out="$2" key="$3"; shift 3
  if [ -n "$key" ]; then
    "$g" bridge create --sha1-rsl "$1" --sha1-head "$2" --sha256-rsl "$3" --sha256-head "$4" -o "$out" --signing-key "$key"
  else
    "$g" bridge create --sha1-rsl "$1" --sha1-head "$2" --sha256-rsl "$3" --sha256-head "$4" -o "$out"
  fi
}

for label in old new; do
  if [ $label = old ]; then G="$OLD"; else G="$NEW"; fi
  d="$B/$label"; mkdir -p "$d"
  mk "$G" "$d/root.json"      "$KEYS/root"     "$SHA1_RSL" "$SHA1_HEAD" "$SHA256_RSL" "$SHA256_HEAD" >>"$LOG" 2>&1
  mk "$G" "$d/unsigned.json"  ""               "$SHA1_RSL" "$SHA1_HEAD" "$SHA256_RSL" "$SHA256_HEAD" >>"$LOG" 2>&1
  mk "$G" "$d/attacker.json"  "$KEYS/attacker" "$SHA1_RSL" "$SHA1_HEAD" "$SHA256_RSL" "$SHA256_HEAD" >>"$LOG" 2>&1
  mk "$G" "$d/policykey.json" "$KEYS/policy"   "$SHA1_RSL" "$SHA1_HEAD" "$SHA256_RSL" "$SHA256_HEAD" >>"$LOG" 2>&1
  mk "$G" "$d/unrel-rsl.json" "$KEYS/root"     "$SHA1_RSL" "$SHA1_HEAD" "$UNRELATED"  "$SHA256_HEAD" >>"$LOG" 2>&1
  mk "$G" "$d/unrel-head.json" "$KEYS/root"    "$SHA1_RSL" "$SHA1_HEAD" "$SHA256_RSL" "$UNRELATED"   >>"$LOG" 2>&1
  mk "$G" "$d/zero-rsl.json"  "$KEYS/root"     "$SHA1_RSL" "$SHA1_HEAD" "$(printf '0%.0s' {1..64})" "$SHA256_HEAD" >>"$LOG" 2>&1
  # Tamper sha256_rsl_tip after signing
  sed "s/\"sha256_rsl_tip\": \"$SHA256_RSL\"/\"sha256_rsl_tip\": \"$UNRELATED\"/" "$d/root.json" > "$d/tampered-rsl.json"
  sed "s/\"sha256_head_oid\": \"$SHA256_HEAD\"/\"sha256_head_oid\": \"$UNRELATED\"/" "$d/root.json" > "$d/tampered-head.json"

  P="$label:"
  check B1 $label "$G" "bridge create: sha256 OID in sha1 field" fail "" "$W" -- "$G" bridge create --sha1-rsl "$SHA256_RSL" --sha1-head "$SHA1_HEAD" --sha256-rsl "$SHA256_RSL" --sha256-head "$SHA256_HEAD" -o "$d/bad.json"
  check B2 $label "$G" "bridge create: truncated sha256 head" fail "" "$W" -- "$G" bridge create --sha1-rsl "$SHA1_RSL" --sha1-head "$SHA1_HEAD" --sha256-rsl "$SHA256_RSL" --sha256-head "${SHA256_HEAD:0:63}" -o "$d/bad2.json"
  check B3 $label "$G" "bridge verify: root-signed bridge" ok "" "$W" -- "$G" bridge verify -f "$d/root.json"
  check B4 $label "$G" "bridge verify: tampered sha256_rsl_tip" fail "" "$W" -- "$G" bridge verify -f "$d/tampered-rsl.json"
  check B5 $label "$G" "bridge verify: unsigned bridge" fail "signature" "$W" -- "$G" bridge verify -f "$d/unsigned.json"

  check V1 $label "$G" "verify-ref: valid root-signed bridge" ok "" "$DST" -- "$G" verify-ref main --bridge-file "$d/root.json" --sha1-repo "$SRC"
  check V2 $label "$G" "verify-ref: unsigned bridge" fail "no embedded SSH signature" "$DST" -- "$G" verify-ref main --bridge-file "$d/unsigned.json" --sha1-repo "$SRC"
  check V3 $label "$G" "ATTACK verify-ref: bridge signed by attacker key" fail "not a root key" "$DST" -- "$G" verify-ref main --bridge-file "$d/attacker.json" --sha1-repo "$SRC"
  check V4 $label "$G" "ATTACK verify-ref: bridge signed by policy (non-root) key" fail "not a root key" "$DST" -- "$G" verify-ref main --bridge-file "$d/policykey.json" --sha1-repo "$SRC"
  check V5 $label "$G" "ATTACK verify-ref: sha256_rsl_tip edited after signing" fail "" "$DST" -- "$G" verify-ref main --bridge-file "$d/tampered-rsl.json" --sha1-repo "$SRC"
  check V6 $label "$G" "ATTACK verify-ref: sha256_head_oid edited after signing" fail "" "$DST" -- "$G" verify-ref main --bridge-file "$d/tampered-head.json" --sha1-repo "$SRC"
  check V7 $label "$G" "ATTACK verify-ref: root-signed, sha256_rsl_tip = unrelated commit" fail "not part of this repository" "$DST" -- "$G" verify-ref main --bridge-file "$d/unrel-rsl.json" --sha1-repo "$SRC"
  check V8 $label "$G" "ATTACK verify-ref: root-signed, sha256_head = unrelated commit" fail "not part of this repository" "$DST" -- "$G" verify-ref main --bridge-file "$d/unrel-head.json" --sha1-repo "$SRC"
  check V9 $label "$G" "ATTACK verify-ref: root-signed, sha256_rsl_tip does not exist" fail "not part of this repository" "$DST" -- "$G" verify-ref main --bridge-file "$d/zero-rsl.json" --sha1-repo "$SRC"
  check V10 $label "$G" "ATTACK verify-ref: substitute a different SHA-1 repo" fail "does not match bridge record" "$DST" -- "$G" verify-ref main --bridge-file "$d/root.json" --sha1-repo "$OTHER"
done

# v1 schema bridge (made by old binary, signed by root) must be rejected by new binary
check V11 new "$NEW" "verify-ref: v1 bridge from PR #23 binary rejected" fail "unsupported bridge schema" "$DST" -- "$NEW" verify-ref main --bridge-file "$B/old/root.json" --sha1-repo "$SRC"
grep -q '"schema_version": "gap1-bridge-v2"' "$B/new/root.json" && s=PASS || s=FAIL
printf "V12\tnew\tnew bridge JSON has schema gap1-bridge-v2\tok\t0\t%s\t%s\n" "$s" "$(grep schema_version "$B/new/root.json" | tr -d ' ')" >> "$RES"
check V13 new "$NEW" "bridge verify prints 'does NOT establish trust' warning" ok "" "$W" -- bash -c "\"$NEW\" bridge verify -f \"$B/new/root.json\" 2>&1 | grep -q 'does NOT establish trust'"

# Continuity: new work after migration still verifies with the same bridge
cd "$DST"; echo more > more.txt; git add more.txt; git commit -q -m "post-migration work"
"$NEW" rsl record main --local-only >>"$LOG" 2>&1
check V14 new "$NEW" "verify-ref after more SHA-256 commits + RSL entries (bridge tips are ancestors)" ok "" "$DST" -- "$NEW" verify-ref main --bridge-file "$B/new/root.json" --sha1-repo "$SRC"

# ---- Snapshot: simulated SHA-1 collision (same OID, different content) ----
SNAP="$W/snap"; cp -r "$SRC" "$SNAP"; cd "$SNAP"
BLOB="$(git rev-parse HEAD:README.md)"
OIDDIGEST() { git cat-file --batch-all-objects --batch-check='%(objectname)' | sort -u | tr -d '\r' | python -c "import sys,hashlib;print(hashlib.sha256('\n'.join(l.rstrip('\n') for l in sys.stdin).encode()).hexdigest())"; }
# unpack everything to loose objects so a single object file can be substituted
mkdir -p "$W/packs"
for p in .git/objects/pack/*.pack; do [ -e "$p" ] || continue; mv "$p" "$W/packs/"; done
rm -f .git/objects/pack/*
for p in "$W"/packs/*.pack; do [ -e "$p" ] && git unpack-objects -q < "$p"; done
test -f ".git/objects/${BLOB:0:2}/${BLOB:2}" || { echo "README blob not loose" >> "$LOG"; }
for label in old new; do
  if [ $label = old ]; then G="$OLD"; else G="$NEW"; fi
  "$G" snapshot freeze -o "../snap-$label.json" -k test >>"$LOG" 2>&1
done
OID_BEFORE="$(OIDDIGEST)"
LOOSE=".git/objects/${BLOB:0:2}/${BLOB:2}"
python - "$LOOSE" <<'EOF'
import sys, zlib, os
p = sys.argv[1]
body = b"backdoored!\n"
os.chmod(p, 0o644)
open(p, "wb").write(zlib.compress(b"blob %d\x00" % len(body) + body))
EOF
git cat-file -p "$BLOB" > "$W/substituted.txt" 2>&1
OID_AFTER="$(OIDDIGEST)"
[ "$OID_BEFORE" = "$OID_AFTER" ] && s=PASS || s=FAIL
printf "C0\t-\tsanity: object name list unchanged after substitution (OID-only digest blind)\tok\t0\t%s\tOID-digest before=%s after=%s; git now returns: %s\n" "$s" "${OID_BEFORE:0:16}" "${OID_AFTER:0:16}" "$(cat "$W/substituted.txt" | tr '\n' ' ')" >> "$RES"
for label in old new; do
  if [ $label = old ]; then G="$OLD"; else G="$NEW"; fi
  check C1 $label "$G" "snapshot verify detects substituted object content (same OID)" fail "" "$SNAP" -- "$G" snapshot verify -m "../snap-$label.json"
done

# ---- Compat mode ----
CM="$W/compat"; mkdir -p "$CM"; cd "$CM"; git init -q -b main --object-format=sha256
git config user.name c; git config user.email c@c; echo a > a; git add a; git -c commit.gpgsign=false commit -q -m a
git config extensions.compatObjectFormat sha1
cp -r "$KEYS" "$W/keys-c" 2>/dev/null
RUST_OK=1; git -C "$CM" rev-parse HEAD 2>&1 | grep -q "requires Rust" && RUST_OK=0
for label in old new; do
  if [ $label = old ]; then G="$OLD"; else G="$NEW"; fi
  if [ $RUST_OK = 0 ]; then
    check M1 $label "$G" "compat repo without GITTUF_COMPAT_MODE is refused" fail "compatObjectFormat" "$CM" -- "$G" trust init -k ../keys/root
    printf "M2	%s	compat mode ON: writes refused as read-only	fail	-	N/A	local git 2.55.0.windows.4 is built without Rust compat support, so no tool can open a compatObjectFormat repo here; covered by unit test TestReferenceUpdatesRefusedInCompatMode
" $label >> "$RES"
    continue
  fi
  check M1 $label "$G" "compat repo without GITTUF_COMPAT_MODE is refused" fail "compatObjectFormat" "$CM" -- "$G" trust init -k ../keys/root
  check M2 $label "$G" "compat mode ON: write (trust init) refused as read-only" fail "read-only" "$CM" -- env GITTUF_COMPAT_MODE=1 "$G" trust init -k ../keys/root
  check M3 $label "$G" "compat mode ON: no gittuf refs were written" ok "" "$CM" -- bash -c "test -z \"\$(git for-each-ref refs/gittuf)\""
  git for-each-ref --format='%(refname)' refs/gittuf | while read r; do git update-ref -d "$r"; done
done

log "DONE"
