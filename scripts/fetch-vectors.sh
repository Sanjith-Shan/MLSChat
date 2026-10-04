#!/usr/bin/env bash
# Fetch the official MLS test vectors and interop harness at a pinned commit.
# They live outside the repo (in $MLS_WORK) so the synced tree stays small.
set -euo pipefail
source "$(dirname "$0")/env.sh"
PIN=cfd450286d1bfd9cd2519b95c80f9771f94a5b1a
DEST="$MLS_WORK/mls-implementations"
if [ ! -d "$DEST/.git" ]; then
  git clone -q https://github.com/mlswg/mls-implementations.git "$DEST"
fi
git -C "$DEST" fetch -q origin
git -C "$DEST" checkout -q "$PIN"
echo "vectors at $DEST/test-vectors (commit $PIN)"
