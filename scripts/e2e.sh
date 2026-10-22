#!/usr/bin/env sh
set -eu

export GOTOOLCHAIN="${GOTOOLCHAIN:-go1.27.3}"
go run ./scripts/e2e
