#!/usr/bin/env bash
# go run -exec helper: run the built binary from the caller's directory.
bin="$1"; shift
cd "$TARGET_DIR" && exec "$bin" "$@"
