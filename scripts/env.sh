# Source this inside WSL. Keeps every heavy artifact on ext4, outside the synced repo.
export MLS_WORK="${MLS_WORK:-$HOME/mlschat-work}"
export RUSTUP_HOME="$MLS_WORK/rustup"
export CARGO_HOME="$MLS_WORK/cargo"
export CARGO_TARGET_DIR="$MLS_WORK/target"
export PATH="$CARGO_HOME/bin:$MLS_WORK/bin:$PATH"
if [ -d "$MLS_WORK/venv" ]; then
  LIBCLANG_DIR="$(ls -d "$MLS_WORK"/venv/lib/python3*/site-packages/clang/native 2>/dev/null | head -1)"
  [ -n "$LIBCLANG_DIR" ] && export LIBCLANG_PATH="$LIBCLANG_DIR"
fi
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
