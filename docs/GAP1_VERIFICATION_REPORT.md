# GAP-1 Genesis Bridge Fixes — Verification Report

* **Branch:** `fix/gap1-bridge-verification`
* **Baseline:** `12329f5` (merge of PR #23 into `main`)
* **Commits verified:** `f2412071` (plan), `b7b094bf` (fixes), `42019300` (demo + lint)
* **Diff vs baseline:** 13 files, +898 / −172 lines
* **Date:** 2026-10-03
* **Environment:** Windows 11, Go 1.27, git 2.55.0.windows.4, OpenSSH 10.3p1, golangci-lint (repo config)

## 1. Verdict

Every fix works as intended. I checked each one with the real `gittuf` CLI
against real SHA-1 and SHA-256 repositories. The same checks were run against
the PR #23 binary for comparison.

* **New code:** all 24 manual checks that can run on this machine pass (22 scenarios plus 2 setup checks). One
  scenario (compat-mode writes) can't run here and is covered by a unit test
  instead (§6).
* **PR #23 code:** accepts 9 of the attack and invalid-input scenarios. These
  are the vulnerabilities fixed on this branch, now confirmed in practice and
  not only by reading code.
* **Demo** (`examples/migrate_demo.sh`): fails on `main`, passes on this branch.
* **Automated tests:** all new and changed tests pass. The only failures are
  pre-existing ones that also occur on `main` (§3).
* **Lint:** `golangci-lint` reports 0 issues on changed lines. `go vet` and
  `gofmt` are clean.

## 2. Change-by-change verification

Each row is one change from this branch, with the evidence that it works.
Scenario IDs refer to §4.

| # | Change (file) | Expected behaviour | Evidence | Result |
|---|---|---|---|---|
| A1 | Signer must be a SHA-256 root key (`experimental/gittuf/bridge_trust.go` `verifyBridgeSignerIsRoot`, called from `verify.go`) | A bridge signed by any non-root key is rejected | V3 (attacker key) and V4 (policy key) rejected with `not a root key`. Old binary accepted both. Unit: `TestVerifyBridgeSignerIsRoot/non-root_key_is_rejected`, `malformed_key_is_rejected` | ✅ |
| A2 | Root threshold > 1 fails closed | Single-signature bridge rejected when root needs 2 signatures | Unit: `TestVerifyBridgeSignerIsRoot/root_threshold_above_one_fails_closed` | ✅ |
| A3 | Valid root-signed bridge still accepted | Happy path passes | V1, V14, demo step 6 | ✅ |
| B1 | Commitment covers all four OIDs, schema `gap1-bridge-v2` (`pkg/gitinterface/bridge.go`) | Editing any field after signing is detected | V5 (`sha256_rsl_tip` edited) and V6 (`sha256_head_oid` edited) rejected with `commitment mismatch`. Old binary accepted V5. B4 (`bridge verify` on tampered file) rejected; old accepted. Unit: `TestVerifyGenesisBridgeTampered` (5 fields), which **failed on `main`** | ✅ |
| B2 | v1 bridges rejected | PR #23-era bridges no longer accepted | V11: bridge from PR #23 binary rejected with `unsupported bridge schema version`. V12: new bridges use `gap1-bridge-v2`. Unit: `TestVerifyGenesisBridgeRejectsOldSchema` | ✅ |
| B3 | OID length and hex validation | SHA-1 fields must be 40 hex chars, SHA-256 fields 64 | B1 and B2 rejected with a clear message. Old binary created both bridges. Unit: `TestNewGenesisBridgeInvalidFields` (9 cases) | ✅ |
| B4 | SHA-256 RSL tip and HEAD must be reachable in the verified repository (`verifyBridgeBindsRepository`) | A root-signed bridge pointing at other SHA-256 coordinates is rejected | V7 (RSL tip = unrelated commit), V8 (HEAD = unrelated commit) and V9 (RSL tip doesn't exist) rejected with `not part of this repository`. Old binary accepted all three | ✅ |
| B5 | Ancestor semantics (not equality) | New work after migration still verifies | V14: extra SHA-256 commit and RSL entry, same bridge still passes | ✅ |
| D | Compat mode is read-only (`pkg/gitinterface/references.go` `ensureWritable`) | All four ref-write functions refuse in compat mode | Unit: `TestReferenceUpdatesRefusedInCompatMode`. M1 (fail-closed without env var) still passes. Manual M2 is N/A (§6) | ✅ (unit) |
| E | Honest `bridge verify` output (`internal/cmd/bridge/bridge.go`) | Says the signature is only valid for the embedded key and points to `verify-ref` | B3 output and V13. Old output said `SSH signature ✔` | ✅ |
| F1 | Content hasher extracted (`hashObjectStream`) | Same OID with different content gives a different digest | C0: object-name list unchanged after substitution, but git returns `backdoored!`. C1: `snapshot verify` reports `Content SHA-256 MISMATCH`. Unit: `TestHashObjectStreamDetectsCollision` | ✅ |
| F2 | Demo fixed (`examples/migrate_demo.sh`) | Demo signs the bridge with the root key and runs `verify-ref --bridge-file` | Old demo exits 1 (`bridge record has no embedded signature`). New demo exits 0 (`full chain of trust established across both epochs ✔`) | ✅ |

C1 also passes with the old binary. That's expected, because PR #23 had
already fixed content hashing. This branch only made that path testable and
corrected its doc comment.

## 3. Automated checks

| Check | Result |
|---|---|
| `go build ./...` | ✅ The only error is in `experimental/hash-agility` (`main` undeclared), which is pre-existing and also on `main` |
| `go vet` (pkg, internal, experimental/gittuf) | ✅ clean |
| `gofmt` on changed files | ✅ clean |
| `golangci-lint --new-from-rev=12329f5` | ✅ 0 issues, after fixing 3 `tparallel` findings in new tests |
| `pkg/gitinterface` (full suite) | 99 pass, 1 skip, **1 fail: `TestStatus`**, which also fails on `12329f5` (pre-existing) |
| `pkg/rsl`, `pkg/githash` | ✅ pass |
| `internal/cmd/bridge`, `internal/cmd/verifyref`, `internal/cmd/snapshot` | ✅ pass |
| `experimental/gittuf`: `TestVerifyRefCrossEpoch` (8 subtests), `TestVerifyBridgeSignerIsRoot` (4 subtests) | ✅ pass |

**Not run here:** the full `experimental/gittuf` suite. Some upstream tests in
it (e.g. `TestAddAndRemoveReferenceAuthorization`) already fail on `main` on
this machine, because Git for Windows' `ssh-keygen` can't load the ECDSA test
key and Windows OpenSSH rejects the temp-dir file permissions. CI on Linux
should run the full suite.

## 4. Manual end-to-end results (real CLI, old vs new)

Setup, built with real `gittuf` commands:

* A SHA-1 repository with root, policy and a `protect-main` rule, signed
  commits, and RSL entries. Verifies on its own (S1 ✅).
* Converted with `git fast-export | fast-import` into a SHA-256 repository with
  a fresh policy using the same root key. Verifies on its own (S2 ✅).
* A second, unrelated SHA-1 repository, and an unrelated commit inside the
  SHA-256 repository.
* Keys: `root`, `policy`, `dev`, and `attacker` (not in any policy).

| ID | Scenario | Expected | PR #23 (old) | This branch (new) |
|---|---|---|---|---|
| B1 | `bridge create` with a SHA-256 OID in a SHA-1 field | reject | ❌ accepted | ✅ rejected |
| B2 | `bridge create` with a truncated SHA-256 HEAD | reject | ❌ accepted | ✅ rejected |
| B3 | `bridge verify` on a root-signed bridge | accept | ✅ | ✅ (with trust warning) |
| B4 | `bridge verify` with `sha256_rsl_tip` edited after signing | reject | ❌ **accepted** | ✅ rejected |
| B5 | `bridge verify` on an unsigned bridge | reject | ✅ | ✅ |
| V1 | `verify-ref --bridge-file` with a valid root-signed bridge | accept | ✅ | ✅ |
| V2 | unsigned bridge | reject | ✅ | ✅ |
| V3 | **attack:** bridge signed by attacker key | reject | ❌ **accepted** | ✅ rejected |
| V4 | **attack:** bridge signed by policy (non-root) key | reject | ❌ **accepted** | ✅ rejected |
| V5 | **attack:** `sha256_rsl_tip` edited after signing | reject | ❌ **accepted** | ✅ rejected |
| V6 | **attack:** `sha256_head_oid` edited after signing | reject | ✅ | ✅ |
| V7 | **attack:** root-signed, `sha256_rsl_tip` = unrelated commit | reject | ❌ **accepted** | ✅ rejected |
| V8 | **attack:** root-signed, `sha256_head` = unrelated commit | reject | ❌ **accepted** | ✅ rejected |
| V9 | **attack:** root-signed, `sha256_rsl_tip` doesn't exist | reject | ❌ **accepted** | ✅ rejected |
| V10 | **attack:** substitute a different SHA-1 repository | reject | ✅ | ✅ |
| V11 | v1 bridge (from PR #23) | reject | n/a | ✅ rejected |
| V12 | new bridge uses `gap1-bridge-v2` | yes | n/a | ✅ |
| V13 | `bridge verify` prints the "does NOT establish trust" warning | yes | n/a | ✅ |
| V14 | more SHA-256 commits and RSL entries after migration, same bridge | accept | n/a | ✅ |
| C0 | sanity: substituted object keeps its OID (an OID-only digest can't see it) | yes | ✅ | ✅ |
| C1 | `snapshot verify` after substituting object content under the same OID | reject | ✅ | ✅ |
| M1 | compat repo without `GITTUF_COMPAT_MODE` | reject | ✅ | ✅ |
| M2 | compat mode on: writes refused | reject | N/A | N/A (§6) |

Totals:

* **New:** 24 / 24 runnable checks pass (including setup checks S1 and S2); 1 N/A.
* **Old:** 9 scenarios behave incorrectly: B1, B2, B4, V3, V4, V5, V7, V8, V9.

Raw results: [`gap1-verification/manual_results.tsv`](gap1-verification/manual_results.tsv)

## 5. How the old binary was run

On this machine, Windows Smart App Control blocks standalone `.exe` files
built from `12329f5` (`Permission denied`, exit 126). I didn't work around the
block. Instead, the old code is run with `go run` through a small wrapper
([`gittuf-old.sh`](gap1-verification/gittuf-old.sh) + [`cdexec.sh`](gap1-verification/cdexec.sh))
that keeps the caller's working directory. Old and new commands get the same
arguments and the same repositories.

## 6. What could not be verified here

* **M2: compat mode refusing writes, via the CLI.** This git build
  (2.55.0.windows.4) has no Rust compat-hash support, so it can't open a
  `compatObjectFormat` repository at all (`fatal: compatibility hash algorithm
  support requires Rust`). The unit test
  `TestReferenceUpdatesRefusedInCompatMode` covers this at the function level.
  It should be checked manually on a Linux git built with Rust support.
* **Full `experimental/gittuf` suite:** see §3. Only the new tests were run.
* **Issue C** (bridge as an entry inside the RSL) is out of scope for this
  branch, as stated in `GAP1_BRIDGE_FIX_PLAN.md`.

## 7. Reproduce

```bash
# new binary
go build -o gittuf-new.exe .
# old code at 12329f5 (used through go run)
git worktree add --detach ../gittuf-pr23-baseline 12329f5
export BASELINE=../gittuf-pr23-baseline

# unit and integration tests
go test ./pkg/gitinterface/ ./pkg/rsl/ ./pkg/githash/ ./internal/cmd/...
go test ./experimental/gittuf/ -run 'TestVerifyRefCrossEpoch|TestVerifyBridgeSignerIsRoot'

# manual end-to-end (writes manual/, manual_log.txt, manual_results.tsv next to the script)
NEW=$PWD/gittuf-new.exe bash docs/gap1-verification/manual_check.sh

# demo
PATH=<dir containing gittuf.exe>:$PATH bash examples/migrate_demo.sh
```
