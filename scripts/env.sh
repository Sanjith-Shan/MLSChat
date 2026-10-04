# Source this inside WSL. Keeps every heavy artifact on ext4, outside the synced repo.
export MLS_WORK="${MLS_WORK:-$HOME/mlschat-work}"
export RUSTUP_HOME="$MLS_WORK/rustup"
export CARGO_HOME="$MLS_WORK/cargo"
export CARGO_TARGET_DIR="$MLS_WORK/target"
export PATH="$CARGO_HOME/bin:$MLS_WORK/bin:$PATH"
if [ -d "$MLS_WORK/venv" ]; then
  LIBCLANG_DIR="$(ls -d "$MLS_WORK"/venv/lib/python3*/site-packages/clang/native 2>/dev/null | head -1)"
  [ -n "$LIBCLANG_DIR" ] && export LIBCLANG_PATH="$LIBCLANG_DIR" && export LD_LIBRARY_PATH="$LIBCLANG_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
fi
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
# The pip libclang wheel ships without clang's builtin headers; borrow GCC's for bindgen.
GCC_INC="$(ls -d /usr/lib/gcc/x86_64-linux-gnu/*/include 2>/dev/null | sort -V | tail -1)"
[ -n "$GCC_INC" ] && export BINDGEN_EXTRA_CLANG_ARGS="-I$GCC_INC"
# protoc for the interop harness's generated gRPC types (user-local download).
[ -x "$MLS_WORK/protoc/bin/protoc" ] && export PROTOC="$MLS_WORK/protoc/bin/protoc"
export PATH="$MLS_WORK/go/bin:$PATH"
