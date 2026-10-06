# GAP-1 — In-Ledger Bridge and RFC Alignment Plan

Branch: `feat/gap1-in-ledger-bridge` (based on `main` @ `d96100c`, after PR #25)

PR #25 made the bridge trustworthy: the signer must be a SHA-256 root key, and
all four OIDs are committed and checked. A re-read of the RFC draft against
`main` still found claims that the code doesn't back up.

## Gaps between the RFC and `main`

1. **In-ledger binding (RFC §1.5 req. 4, §3.1 principle 3, §3.3).** The RFC says
   the bridge is recorded as a `GenesisBridgeEntry` in
   `refs/gittuf/reference-state-log`. On `main`, verification only reads a loose
   `genesis-bridge.json`. No command writes a bridge entry to the RSL, and
   `rsl.GetLatestGenesisBridgeEntry` is never called.
2. **`gittuf bridge verify` and root authority (RFC §3.7).** The RFC says it
   verifies the "root authority" signature. On `main`, it only checks the
   signature against the key embedded in the bridge, and warns that this
   doesn't establish trust.
3. **Binding description (RFC §3.7).** The RFC says "3-way binding". The
   commitment is now over four OIDs (`gap1-bridge-v2`).
4. **Naming and prior art (RFC title, §2.4, §3).** The RFC calls itself "GAP-1"
   without citing upstream gittuf's GAP-1 or issue #104, or the existing PoC
   repositories.

## Plan

### 1 → Record the bridge in the RSL (code)

* `rsl.GenesisBridgeEntry` carries the whole signed v2 bridge:
  * schema version;
  * SHA-1 RSL tip and HEAD;
  * SHA-256 RSL tip and HEAD;
  * timestamp and commitment;
  * the sshsig signature (base64) and the signer's public key.

  The legacy constructor that computed a different, unsigned commitment is
  removed.
* New command `gittuf bridge record -f <bridge.json>`, run in the SHA-256
  repository. It checks the bridge before writing it:
  * the bridge's commitment and signature are valid;
  * the signer is a SHA-256 root key;
  * the bridge's `sha256_rsl_tip` is the **current** RSL tip, so the entry is
    appended directly on top of the state it commits to;
  * no bridge has been recorded yet (one bridge per repository).
* `gittuf verify-ref <ref> --sha1-repo <path>` (no `--bridge-file`) reads the
  bridge from the RSL. In addition to every check from PR #25, the bridge
  entry's parent in the RSL must be the bridge's `sha256_rsl_tip`.
* `--bridge-file` keeps working. If the RSL also holds a bridge, the two must
  have the same commitment.
* Verification never trusts the RSL entry just because it is in the RSL. Every
  check also runs on entries written directly, bypassing `bridge record`.
* Normal `verify-ref` must keep working with a bridge entry in the RSL. The
  RSL walkers only consider reference-updater entries; a test covers this.

### 2 → `gittuf bridge verify` checks root authority (code)

When run inside a gittuf repository with a policy (the SHA-256 repository),
`bridge verify` also requires the signer to be one of that repository's root
keys, and fails otherwise. Outside such a repository it keeps the existing
warning that trust isn't established.

### 3, 4 → RFC text (docs)

`docs/GAP1_RFC_CORRECTIONS.md` gives replacement text for each affected RFC
section, ready to paste into the Google Doc:

* the in-ledger model;
* `bridge record`;
* the four-OID commitment;
* SHA-256 root authority with threshold 1;
* the updated test list;
* a "Relationship to upstream GAP-1 and prior art" section, with a title
  that's no longer a second "GAP-1".

### Demo

`examples/migrate_demo.sh` records the bridge in the RSL and verifies with
`verify-ref main --sha1-repo …`, without a bridge file.

## Tests

* `pkg/rsl`: a bridge entry round-trips through commit and parse, keeping all
  new fields.
* `experimental/gittuf`:
  * record, then verify from the ledger;
  * normal `VerifyRef` still passes with a bridge entry in the RSL;
  * record is rejected for a forged signer, a moved RSL tip, or a second bridge;
  * a forged entry committed directly to the RSL is rejected;
  * an entry not placed on its `sha256_rsl_tip` is rejected;
  * a ledger/file mismatch is rejected;
  * the exported signer check accepts root keys and rejects other keys.
