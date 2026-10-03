# GAP-1 Genesis Bridge — Review Fix Plan

Branch: `fix/gap1-bridge-verification` (based on `main` @ `12329f5`, the merge of PR #23)

PR #23 fixed content hashing, added SSH signing to the bridge, added a
cross-epoch `verify-ref` walk and added `GITTUF_COMPAT_MODE`. A re-review of
the merged code found the issues below. Each one is confirmed against the code
at `12329f5`.

---

## Issues found

### A. Bridge signature is self-certifying (critical)

`VerifyGenesisBridgeSignature` verifies the signature against
`bridge.SignerPublicKey`, a key taken from the bridge JSON itself. Nothing checks
that key against gittuf's root of trust. Anyone can generate a key, sign an
arbitrary bridge, embed the key, and `verify-ref --bridge-file` reports
`signature ✔`. The RFC draft claims the check verifies a "root authority"
signature, which the code does not do.

### B. SHA-256 epoch is not bound by the bridge (regression)

* PR #23 changed the commitment to
  `genesis-bridge|sha1|<sha1RSLTip>|<sha1HeadOID>|<sha256HeadOID>|<ts>`, which
  drops `sha256_rsl_tip`. That field can be edited without detection.
* `VerifyRefCrossEpoch` never compares `sha256_rsl_tip` / `sha256_head_oid`
  with the SHA-256 repository being verified. A valid bridge "passes" next to
  any SHA-256 repository.
* The existing test `TestVerifyGenesisBridgeTampered` catches exactly this and
  **fails on `main`**.
* OID fields are not validated, so a SHA-1 field could hold a 64-char value and
  vice versa.

### C. In-ledger binding is not used

The RFC presents `GenesisBridgeEntry` in the RSL as the core binding. In code,
verification uses a loose JSON file (`--bridge-file`), and
`rsl.GetLatestGenesisBridgeEntry` is never called. No command writes a
`GenesisBridgeEntry` into the RSL.

### D. `GITTUF_COMPAT_MODE` is not read-only

The RFC says compat mode is "read-only" and "prohibited for policy enforcement
and merge gating". In code, setting the env var logs a warning and gittuf then
behaves normally, including writing RSL and policy refs.

### E. `gittuf bridge verify` overstates its result

The standalone command prints `SSH signature ✔` after checking the signature
against the embedded key only. A reader takes this as the bridge being trusted.

### F. No tests for any PR #23 code

PR #23 added no tests for signing, the cross-epoch walk, content hashing's
collision property, or compat mode.

---

## Fixes (this branch)

### A → Bind the signer to the SHA-256 root of trust

* In `VerifyRefCrossEpoch`, load the SHA-256 repository's current policy state
  and its root principals and threshold.
* The bridge signer key must equal one of the root keys (SSH key bytes compared
  exactly). Otherwise fail with `ErrBridgeSignerNotAuthorized`.
* The bridge carries a single signature, so if the root threshold is greater
  than 1, fail closed with `ErrBridgeThresholdUnsupported` rather than silently
  accept one signature.
* Rationale: the SHA-256 repository is what the verifier is already trusting.
  A bridge signed by its root says "my prior history ends at SHA-1 RSL tip X".
  An attacker who doesn't hold a root key can't move X, and the SHA-1 repository
  at X is then verified under its own policy. This is the same pattern as TUF
  root rotation, where the new state is vouched for by a key the verifier
  already trusts.

### B → Commit to all four OIDs and check the SHA-256 side

* New schema `gap1-bridge-v2`. The commitment is
  `genesis-bridge|gap1-bridge-v2|sha1|<sha1RSLTip>|<sha1HeadOID>|sha256|<sha256RSLTip>|<sha256HeadOID>|<RFC3339 ts>`.
  v1 bridges are rejected (fail closed). Re-create them with `gittuf bridge create`.
* `NewGenesisBridge` and verification validate OID lengths: SHA-1 fields must be
  40 hex chars and SHA-256 fields 64 hex chars.
* `VerifyRefCrossEpoch` additionally requires:
  * `sha256_rsl_tip` is in the SHA-256 RSL (equal to or an ancestor of the
    current RSL tip);
  * `sha256_head_oid` is equal to or an ancestor of the verified ref's tip.

### C → Documented follow-up, not in this branch

Writing a `GenesisBridgeEntry` into the live RSL changes what the policy
verifier sees when walking entries (`internal/policy/verify.go` only knows
reference and propagation entries). Doing this safely needs its own design and
tests. For this branch:

* The JSON bridge, now trust-anchored by A and bound by B, is the verification
  anchor.
* The RFC draft must describe this "bridge file as cryptographic anchor" model
  and list in-RSL binding as future work.

### D → Make compat mode actually read-only

`SetReference`, `CheckAndSetReference`, `DeleteReference` and
`SetSymbolicReference` return `ErrCompatModeReadOnly` when the repository is
loaded in compat mode. Every gittuf state change (RSL, policy, attestations) goes
through a ref update, so no gittuf state can be written. Verification is
unaffected.

### E → Honest CLI output

`gittuf bridge verify` reports that the signature is valid for the **embedded**
key and that trust is only established by
`gittuf verify-ref --bridge-file ... --sha1-repo ...`.

### F → Tests

* Bridge: tampering any single field fails the commitment check; sign/verify
  round-trip; tampered signature; signature by a different key; unsigned bridge;
  v1 schema rejected; bad OID lengths rejected.
* Content hashing: the object-stream hasher is split out so a simulated SHA-1
  collision (same OID, different content) can be tested. It must produce a
  different digest.
* Trust: the signer key is accepted when it is a root key and rejected
  otherwise; threshold > 1 is rejected.
* Compat mode: ref writes are refused in compat mode.

---

## RFC draft changes needed (Google Doc, not in this repo)

1. §3.6 step 1: "root authority signature" is now true, but say *which* root
   (the SHA-256 epoch's root) and that threshold > 1 is not yet supported.
2. §3.3: describe the bridge JSON as the anchor; move in-RSL `GenesisBridgeEntry`
   to future work (issue C).
3. §3.5: compat mode refuses all ref updates, which keeps the "read-only" claim
   honest now.
4. Rename the proposal away from "GAP-1", or frame it as a design for upstream
   GAP-1's open TODOs. Cite upstream GAP-1 and issue #104.

---

## Known limitations after this branch

* The bridge is checked against the SHA-256 repository's **current** root
  keys. If the root is rotated later, the bridge must be re-signed by the new
  root. That's cheap, because only the root holder signs, not historical
  authors.
* Single signature only. Root thresholds above 1 are rejected (fail closed),
  not supported.
* In-RSL binding (issue C) is still open.

## Test status

New and changed tests, all passing locally:

| Package | Tests |
|---|---|
| `pkg/gitinterface` | `TestNewGenesisBridgeInvalidFields`, `TestVerifyGenesisBridgeTampered` (all 5 fields), `TestVerifyGenesisBridgeRejectsOldSchema`, `TestSignAndVerifyGenesisBridgeSignature`, `TestHashObjectStreamDetectsCollision`, `TestReferenceUpdatesRefusedInCompatMode` |
| `experimental/gittuf` | `TestVerifyRefCrossEpoch` (real SHA-1 + SHA-256 repos with policies: happy path, forged signer, non-policy signer, 3 SHA-256 binding failures, 2 SHA-1 mismatches), `TestVerifyBridgeSignerIsRoot` |

Notes on running locally (Windows):

* The cross-epoch fixture signs policy metadata with the RSA root key only.
  On this machine, Git for Windows' `ssh-keygen` (OpenSSH 10.3) cannot load the
  ECDSA test key, and Windows OpenSSH rejects the temp-dir file ACLs. This also
  breaks some existing upstream tests (e.g. `TestAddAndRemoveReferenceAuthorization`)
  on `main` without these changes.
* `pkg/gitinterface` `TestStatus` fails on `main` without these changes too
  (pre-existing).
