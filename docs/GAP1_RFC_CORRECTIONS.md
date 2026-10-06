# RFC Draft — Corrections to Match the Code

Replacement text for the Google Doc "RFC Draft: Continuous Cryptographic
Provenance Across Hash Epoch Transitions in Gittuf (GAP-1)", checked against
branch `feat/gap1-in-ledger-bridge`.

Each block says **where** it goes and gives text to paste. Sections not listed
here (§1.1–§1.4, §2.1–§2.3, §3.2, §3.4, §3.5, §3.8) are consistent with the code
and need no change.

---

## 0. Global: naming

"GAP-1" is already taken upstream: gittuf's GAP-1 is *"Providing SHA-256
Identifiers Alongside Existing SHA-1 Identifiers"* (sponsor: Aditya Sirish A
Yelgundhalli, `docs/gaps/1`, not implemented). Presenting this RFC as "GAP-1
(gittuf Agility Protocol 1)" reads as a competing GAP with the same number.

**Title — replace with:**

> RFC Draft: Continuous Cryptographic Provenance Across Hash Epoch Transitions
> in gittuf — a Genesis Bridge Design for GAP-1

**Body — find and replace:**

| Find | Replace with |
|---|---|
| `GAP-1 (gittuf Agility Protocol 1)` | `the Genesis Bridge design` |
| `the GAP-1 Architecture` (heading of §3) | `the Genesis Bridge Architecture` |
| `In production GAP-1` (§3.9 note) | `In a production deployment` |
| other standalone `GAP-1` that names *this* proposal | `this proposal` |

Code identifiers such as `gap1-bridge-v2` and `pkg/.../bridge.go` can stay:
they implement work towards upstream GAP-1.

---

## 1. New section §2.5 — insert after §2.4

> ### 2.5 Relationship to Upstream GAP-1 and Prior Art
>
> **Upstream status.** gittuf tracks hash agility as GAP-1, *Providing SHA-256
> Identifiers Alongside Existing SHA-1 Identifiers* (`docs/gaps/1`, not
> implemented), and roadmap issue #104 (open since 2023). GAP-1 proposes a
> gittuf-maintained SHA-1→SHA-256 mapping for repositories that stay on SHA-1.
> It leaves open how that mapping is stored, synchronised and secured. The
> prototype for that approach (PR #105) was closed in 2024 to wait for Git's
> own compatibility mode. Native SHA-256 repository support landed in PR #1472
> (v0.16.0), which rejects `compatObjectFormat` repositories.
>
> **What this proposal adds.** This proposal covers the case GAP-1 doesn't:
> an existing SHA-1 repository that is *converted* to SHA-256. It doesn't
> maintain a per-object mapping. Instead it records one signed Genesis Bridge
> that binds the final SHA-1 RSL state to the first SHA-256 RSL state, and it
> extends `verify-ref` to cross that bridge.
>
> **Prior art it builds on.**
> * TUF root rotation (a new state vouched for by a key the verifier already
>   trusts).
> * Transparency-log checkpoints.
> * git-evtag (a strong digest over the full object closure).
> * Fossil's SHA-1→SHA3-256 transition (mixed-hash history, algorithm told
>   apart by digest length).
> * Git's hash-function-transition design, whose SHA-1↔SHA-256 mapping is
>   local and never transferred over the network.
>
> **What is new.** The bridge is recorded in gittuf's RSL. It must be signed by
> a root key of the SHA-256 repository. `verify-ref` walks the SHA-256 RSL,
> crosses the bridge, and keeps verifying the frozen SHA-1 RSL and policy
> history under the original keys, without re-signing historical commits.
>
> **Prototype history.** The snapshot, bridge, CLI and verification code was
> developed in the hash-agility PoC repositories (Aarav Anand, Aashish Pandit,
> Aastha Priya and Shubham:
> `github.com/{Aaravanand00,Aastha-spec-tech,imshubham22apr-gif}/gittuf-hash-agility-poc`).

**Also in §2.4** — replace the last sentence
"This missing primitive is precisely what GAP-1 (gittuf Agility Protocol 1)
introduces." with:

> This proposal introduces that primitive: the Genesis Bridge.

---

## 2. §3.1 — Core Design Principle 3

Replace principle 3 with:

> 3. **Native In-Ledger Binding:** The signed Genesis Bridge is recorded with
>    `gittuf bridge record` as a `GenesisBridgeEntry` commit in the SHA-256
>    repository's Reference State Log, directly on top of the RSL tip it commits
>    to. Being in the RSL does not make the entry trusted: verification still
>    re-derives the commitment, checks the signature, and requires the signer to
>    be a root key.

---

## 3. §3.3 — replace the whole section

> ### 3.3 Pillar 2: In-Ledger Dual-Epoch Genesis Bridge
> (`pkg/gitinterface/bridge.go`, `pkg/rsl/bridge_entry.go`, `experimental/gittuf/bridge_ledger.go`)
>
> After the object store is converted to SHA-256 and gittuf is initialised in
> the new repository, a Genesis Bridge binds the final coordinates of the SHA-1
> epoch to the first coordinates of the SHA-256 epoch.
>
> **1. Bridge record and commitment (schema `gap1-bridge-v2`).** The commitment
> covers all four OIDs, so changing any of them invalidates the signature:
>
> ```
> commitment = SHA-256("genesis-bridge|gap1-bridge-v2|sha1|<sha1_rsl_tip>|<sha1_head_oid>|sha256|<sha256_rsl_tip>|<sha256_head_oid>|<created_at RFC3339>")
> ```
>
> * OIDs are validated by epoch: SHA-1 fields must be 40 hex characters,
>   SHA-256 fields 64.
> * The commitment is signed with sshsig (namespace `gittuf-bridge`, SHA-512).
>   The signer's public key is embedded in the record.
> * Bridges with any other schema version are rejected.
>
> **2. Recording in the RSL.** `gittuf bridge record -f genesis-bridge.json`,
> run in the SHA-256 repository, appends a `GenesisBridgeEntry` to
> `refs/gittuf/reference-state-log`. It refuses to record unless:
> * the commitment and signature are valid;
> * the signer is a root key of the repository's current policy;
> * `sha256_rsl_tip` is the current RSL tip, so the entry lands directly on top
>   of the state it commits to;
> * the RSL has no Genesis Bridge yet.
>
> **3. In-ledger commit message format:**
>
> ```
> RSL Genesis Bridge Entry
>
> schemaVersion: gap1-bridge-v2
> priorEpochHashAlgo: sha1
> priorEpochRSLTip: <40-hex SHA-1 RSL tip>
> priorEpochHeadOID: <40-hex SHA-1 HEAD>
> currentEpochRSLTip: <64-hex SHA-256 RSL tip; the entry's parent>
> currentEpochHeadOID: <64-hex SHA-256 HEAD>
> commitmentDigest: <64-hex commitment>
> frozenTimestamp: <RFC3339 UTC>
> bridgeSignature: <base64 of armored sshsig signature>
> bridgeSignerPublicKey: ssh-ed25519 AAAA...
> bridgeDescription: GAP-1 Genesis Bridge: ...
> number: <RSL entry number>
> ```
>
> Ordinary RSL processing (`verify-ref`, reference lookups) only considers
> reference-updater entries, so it isn't affected by the bridge entry.

---

## 4. §3.6 — replace the phase list

> The cross-epoch walk runs when `gittuf verify-ref <ref> --sha1-repo <path>`
> is given:
>
> 1. **Load the bridge.** By default the `GenesisBridgeEntry` is read from the
>    SHA-256 RSL. `--bridge-file` may supply the bridge JSON instead; if the
>    RSL also has a bridge, both must have the same commitment. More than one
>    bridge entry in the RSL is rejected.
> 2. **Commitment and signature (sshsig).** Re-derive the commitment and verify
>    the signature against the embedded key.
> 3. **Root authority.** The signer must be a root key of the SHA-256
>    repository's current policy. A root threshold above 1 is rejected (fail
>    closed), because a bridge carries one signature.
> 4. **SHA-1 anchor.** The SHA-1 repository's actual RSL tip must equal
>    `sha1_rsl_tip`, so a different SHA-1 repository can't be substituted.
> 5. **SHA-256 epoch walk.** Full policy verification of the SHA-256 RSL.
>    Then `sha256_rsl_tip` must be reachable from the current RSL tip, and
>    `sha256_head_oid` from the verified ref. For an in-ledger bridge, the
>    entry's parent must be `sha256_rsl_tip`.
> 6. **SHA-1 epoch walk.** Full policy verification of the SHA-1 RSL back to
>    its first entry under the original keys. The verified tip must equal
>    `sha1_head_oid`.

---

## 5. §3.7 — replace items 2 and 3

> **2. gittuf bridge**
>
> * `gittuf bridge create --sha1-rsl <oid> --sha1-head <oid> --sha256-rsl <oid> --sha256-head <oid> --signing-key <root key> -o genesis-bridge.json`:
>   creates the `gap1-bridge-v2` record with a commitment over all **four**
>   OIDs and signs it. `--sha256-rsl` must be the SHA-256 RSL tip at the time
>   the bridge is recorded.
> * `gittuf bridge record -f genesis-bridge.json`: records the signed bridge in
>   the SHA-256 RSL (§3.3).
> * `gittuf bridge verify -f genesis-bridge.json`: checks the commitment and
>   signature. When run inside the SHA-256 repository, it also requires the
>   signer to be one of that repository's root keys. Elsewhere it reports that
>   root authority wasn't checked.
>
> **3. gittuf verify-ref (cross-epoch mode)**
>
> ```
> gittuf verify-ref main --sha1-repo /path/to/sha1-repo                               # bridge from the RSL
> gittuf verify-ref main --sha1-repo /path/to/sha1-repo --bridge-file bridge.json     # bridge from a file
> ```

---

## 6. §3.9 — replace item 1 (test list)

> 1. **Automated tests** (all passing):
>    * `pkg/gitinterface`: `TestVerifyGenesisBridgeTampered` (each committed
>      field), `TestSignAndVerifyGenesisBridgeSignature`,
>      `TestNewGenesisBridgeInvalidFields`, `TestHashObjectStreamDetectsCollision`,
>      `TestReferenceUpdatesRefusedInCompatMode`.
>    * `pkg/rsl`: `TestGenesisBridgeEntryMessageRoundTrip`,
>      `TestGenesisBridgeEntryValidation`, `TestGenesisBridgeEntryCommitAndLoad`.
>    * `pkg/githash`: `TestDetectAlgorithm`, `TestDetectAlgorithmFromHex`,
>      `FuzzNewHash`.
>    * `experimental/gittuf`: `TestVerifyRefCrossEpoch` (real SHA-1 and
>      SHA-256 repositories with policies; forged and misbound bridges
>      rejected), `TestVerifyBridgeSignerIsRoot`, and `TestGenesisBridgeInLedger`.
>      The last one covers recording, verifying from the RSL, ordinary
>      `verify-ref` with a bridge entry present, and rejecting forged,
>      tampered, misplaced or duplicate RSL entries.
>    * Manual end-to-end check with the real CLI against the earlier PoC binary:
>      the earlier binary accepted 9 attack and invalid-input cases that the
>      current code rejects (`docs/GAP1_VERIFICATION_REPORT.md`).

---

## 7. Known limitations (add to §3.8 or a new §3.10)

> * The bridge is checked against the SHA-256 repository's *current* root keys.
>   After a root rotation, the bridge must be re-signed by the new root.
> * Single signature only; root thresholds above 1 are rejected rather than
>   supported.
> * Compatibility mode (`GITTUF_COMPAT_MODE`) is read-only: all reference
>   updates are refused.
