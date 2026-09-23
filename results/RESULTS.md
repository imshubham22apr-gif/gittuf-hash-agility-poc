# Gittuf Hash Agility (GAP-1) PoC Results

## Executive Summary
This PoC shows that a gittuf-protected repository can be moved from SHA-1 to SHA-256 by starting a fresh gittuf chain in the new repository and linking it to the old one with signed records, without rewriting any historical signature. A naive copy of the gittuf metadata fails closed. The links between the two epochs (the genesis bridge in Scenario D and the hash-equivalence attestation in Scenario E) are stored inside the new repository's `refs/gittuf/attestations` and recorded in its RSL, but they are verified by `ssh-keygen` in this PoC, **not by gittuf**. `gittuf verify-ref` only shows that it tolerates them. Making gittuf enforce them needs a gittuf change (see Open Questions).

Every statement below points at a log in `results/`. All logs were regenerated in one run with gittuf 0.16.0 and Git 2.55.0.windows.4.

## Verification Matrix

| Scenario | Description | Expected | Actual | Verified by | Log |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **A: Baseline** | Original SHA-1 gittuf repository | PASS | **PASS** (exit 0) | gittuf | `03-matrix-scenario-a.txt` |
| **B: Naive Copy** | Fast-exported to SHA-256, `refs/gittuf/*` carried along | FAIL | **FAIL** (exit 1) | Git, then gittuf | `03-matrix-scenario-b.txt` |
| **C: Fresh Chain** | Fresh SHA-256 repo, new gittuf chain, no link to history | PASS | **PASS** (exit 0) | gittuf | `03-matrix-scenario-c.txt` |
| **D: Genesis Bridge** | Scenario C + signed genesis record committed in `refs/gittuf/attestations` | D1-D5 as expected | **All 5 as expected** (exit 0) | ssh-keygen (D2, D3); gittuf only tolerates it (D5) | `03-matrix-scenario-d.txt` |
| **E: Attestation** | DSSE hash-equivalence record (SHA-1 head -> SHA-256 head) added to the same ref | verify PASS, tamper FAIL | **As expected** | ssh-keygen + PoC helper, not gittuf | `04-attestation.txt` |
| **Probe 3: Signed tags** | SSH-signed `v1.0.0` migrated with `strip` and `verbatim` | no valid signature after migration | **No valid signature** in either mode | git verify-tag | `05-edge.txt` |

## Naive Migration Verdict (Scenario B)
**Verdict: fails closed, at two separate layers.** Neither layer is a gittuf feature built for this case. Both are side effects of the object IDs changing.

1. **Git refuses the cross-algorithm fetch.** Fetching `refs/gittuf/*` from the SHA-1 repo into the SHA-256 repo fails outright:
   > `fatal: mismatched algorithms: client sha256; server sha1` (`FETCH EXIT: 128`)
2. **gittuf cannot resolve the SHA-1 IDs inside the RSL.** The RSL arrives anyway, because `git fast-export --all` exports every ref, `refs/gittuf/*` included. The RSL commits get new SHA-256 IDs, but the target IDs written in their messages stay 40-character SHA-1. `verify-ref` then looks one up and fails:
   > `Error: unable to inspect if object is commit: ... cat-file -t 6ee002a59681509586feb316fe18f98c38e66d26`: `fatal: Not a valid object name 6ee002a59681509586feb316fe18f98c38e66d26` (`EXIT: 1`)

An earlier version of this section described only layer 2 and called it a deliberate defence. It is fail-closed behaviour, but nothing in gittuf targets hash migration specifically.

## Genesis Bridge (Scenario D)
The genesis record (`old_rsl_tip`, `commitment_sha256`, `old_root_key_fingerprint`, `created_at`) is signed with the **old** root key. It is committed into the new repository as `refs/gittuf/attestations:hash-migration/genesis-bridge.json` (plus `.sig`), and that ref update is recorded in the new RSL. The working-tree copies are deleted before any check runs, so every check reads from the ref.

| Check | What it shows | Result |
| :--- | :--- | :--- |
| D1 | The record can be read from the ref (`git cat-file`) | exit 0 |
| D2 | The signature over the blob from the ref verifies against the old root key (`ssh-keygen -Y verify`) | exit 0 |
| D3 | A one-character change to that payload fails verification | exit 255 (expected fail) |
| D4 | `gittuf rsl log` has an entry for `refs/gittuf/attestations` whose target is the commit holding the record | found |
| D5 | `gittuf verify-ref main` still passes with the extra tree entry present | exit 0 |

**Limits:** `gittuf verify-ref` does not read `hash-migration/*`. D5 shows the record is safe to embed, not that gittuf checks it. The previous run of this scenario wrote the record as loose files that were never committed, so it was the same as Scenario C. That result is withdrawn.

## Hash-Equivalence Attestation (Scenario E)
A DSSE envelope with predicate `https://gittuf.dev/predicate/hash-equivalence/v1`, mapping the SHA-1 `main` head to the SHA-256 `main` head, is signed with the old root key. It is added as `hash-equivalence.json` next to `hash-migration/` in `refs/gittuf/attestations`, keeping the Scenario D entry and chaining on the previous commit, and it is recorded in the RSL. `gittuf verify-ref main` still passes afterwards.

**Limits:** the positive and tamper tests rebuild the DSSE pre-authentication encoding in shell and check it with `ssh-keygen`. The envelope is built by the PoC's own helper (`scripts/04-dsse-helper.go`). gittuf does not verify this attestation.

## Snapshot Anchoring Without a Transparency Log
**What replaced Rekor:** an ID-only commitment (branch and tag tips, RSL tip, policy tip and root key fingerprint, sorted and deduplicated, then SHA-256 hashed) inside `snapshot-manifest.json`, signed with the offline root key, plus the SHA-256 of the archived bundle.

**Why:** private repositories cannot publish ref names or object IDs to a public log such as Sigstore/Rekor.

**What this gives up:**
- **It does give:** integrity, and rewind detection for anyone who already holds the trusted root public key. A changed manifest or bundle no longer matches the signature or hash, and the commitment is reproducible (Probe 4, `05-edge.txt`).
- **No split-view protection.** The holder of the root key can sign two different manifests and show a different one to each party. Nothing public records which manifest came first or which one everyone saw.
- **No third-party witness.** Everything depends on the root key holder being honest and the key staying secret.
- **The optional RFC 3161 timestamp** (freetsa.org) only proves the manifest existed at a certain time. It is off by default and runs only with `TIMESTAMP=1`, because it needs network access. The logged run did not use it.

## Signed Tags (Probe 3)
`v1.0.0` in the SHA-1 repository is SSH-signed, and `git verify-tag` passes there (`01-baseline.txt`, exit 0).
- `git fast-export --all` without a `--signed-tags` mode stops: `fatal: encountered signed tag ...; use --signed-tags=<mode> to handle it` (exit 128).
- `--signed-tags=strip`: the imported tag has no signature block, and `verify-tag` prints `error: no signature found` (exit 1).
- `--signed-tags=verbatim`: the signature block is kept byte for byte, but `verify-tag` prints `Signature verification failed: incorrect signature` (exit 1). The signed text includes the tag's `object` line, which now names a SHA-256 object.

Conclusion: no tag signature survives a SHA-1 -> SHA-256 conversion, which supports keeping the old repository or bundle as the evidence for signatures made before migration. An earlier run checked a tag named `v1.0` that did not exist, against an unsigned tag. Its conclusion is withdrawn.

## `compatObjectFormat` Findings (Probe 1)
Setting `extensions.compatObjectFormat sha1` did **not** give working SHA-1 lookups with this Git build. Importing fails with `fatal: compatibility hash algorithm support requires Rust`, and `git cat-file -p <old SHA-1 head>` fails. gittuf refuses the repository before any lookup:
> `Error: gittuf does not support repositories with extensions.compatObjectFormat enabled: compat object format is set to 'sha1'`

So this probe shows only that gittuf rejects compat-mode repositories outright. It cannot show how gittuf would behave if Git could resolve old IDs, because that needs a Git built with Rust support.

## Recommendations for GAP-1
1. **Don't rewrite history (Approach A).** Converting to SHA-256 invalidates tag signatures in every export mode (Probe 3), and rewriting RSL text would invalidate RSL signatures the same way.
2. **Start fresh and bridge (Approach B/D).** Add the ID-only commitment to gittuf as a native `gittuf snapshot` command, and teach `verify-ref` to read and check a genesis record like the one embedded in Scenario D.
3. **Make hash-equivalence attestations part of gittuf (Approach C).** Have `verify-ref` check `https://gittuf.dev/predicate/hash-equivalence/v1` when it reaches the boundary between the old and new chains. Today the PoC checks it outside gittuf.
4. **Fetch `refs/gittuf/*` when cloning.** A plain clone does not bring the gittuf refs, and verification fails on the new machine (Probe 2).

## Open Questions for Maintainers
- Should the genesis and hash-equivalence records live in `refs/gittuf/attestations` (as in this PoC, under `hash-migration/` and `hash-equivalence.json`), or in the RSL as a dedicated `EpochTransitionEntry`, so they are always fetched and checked in order?
- What should `verify-ref` do when it reaches the epoch boundary: require the genesis record, or treat it as advisory?
- Will gittuf keep refusing `compatObjectFormat` repositories once Git's Rust-based compat support is common?
- Should a `gittuf snapshot` command print the canonical commitment input to stdout before hashing it, so auditors can inspect it?
