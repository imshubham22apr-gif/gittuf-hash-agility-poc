#!/usr/bin/env bash
# Runs gittuf built from 12329f5 (PR #23 merge) via `go run`, from the caller's
# directory. Used as the "old" binary in manual_check.sh. Set BASELINE to a
# worktree checked out at 12329f5 (git worktree add --detach <dir> 12329f5).
export TARGET_DIR="$PWD"
here="$(cd "$(dirname "$0")" && pwd)"
exec go -C "${BASELINE:?set BASELINE to a 12329f5 worktree}" run -exec "bash $here/cdexec.sh" . "$@"
