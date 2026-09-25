#!/usr/bin/env bash
# Compile and lint the `msb` CLI and its dependency graph for a Windows target
# from a macOS or Linux host.
#
# `cargo clippy --workspace` only sees the code the host platform compiles. An
# item gated behind `cfg(windows)`, `cfg(unix)`, or `cfg(target_os = "...")` that
# is used on one platform and not the other becomes an unused import or dead code
# on the other, and no local gate compiles that side. `cargo check` and
# `cargo clippy` for the Windows target type-check it without linking, so no
# MSVC, no Windows SDK, and no libkrunfw.dll import library is involved.
#
# This mirrors the "Check msb" and "Clippy msb" steps of the `windows-quality`
# job in .github/workflows/check.yml, with `x86_64-pc-windows-gnu` in place of
# the x86_64 MSVC target CI builds. See the "Cross-target (Windows) check"
# section of DEVELOPMENT.md for what that leaves uncovered.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

# The Rust target this script checks, and the package and feature set the Windows
# CI jobs compile. The shim below repeats the target in zig's spelling because it
# runs as its own process.
readonly RUST_TARGET=x86_64-pc-windows-gnu
readonly PACKAGE=microsandbox-cli
readonly FEATURES=net,ssh

case "$(uname -s)" in
Darwin | Linux) ;;
*)
  cat >&2 <<EOF
error: this check cross-compiles from a macOS or Linux host; on Windows the
native MSVC check already covers it:
    cargo clippy --no-default-features --features $FEATURES -p $PACKAGE --target x86_64-pc-windows-msvc -- -D warnings
EOF
  exit 1
  ;;
esac

command -v cargo >/dev/null || {
  echo "error: cargo is not on PATH." >&2
  exit 1
}
command -v rustup >/dev/null || {
  echo "error: rustup is required to install the $RUST_TARGET target." >&2
  exit 1
}
command -v zig >/dev/null || {
  cat >&2 <<'EOF'
error: zig is not on PATH.
x86_64-pc-windows-gnu needs a C toolchain for the C dependencies of this
workspace (ring, aws-lc-sys). The MSVC target would need the Windows SDK, which
a macOS or Linux host does not have unless it is provisioned separately, so this
check uses `zig cc` instead.
    brew install zig                     # macOS
    https://ziglang.org/download/         # Linux
EOF
  exit 1
}

if ! rustup target list --installed | grep -qx "$RUST_TARGET"; then
  echo "==> Installing the $RUST_TARGET Rust target"
  rustup target add "$RUST_TARGET"
fi

# cc-rs resolves this target to the LLVM triple `x86_64-pc-windows-gnu` and
# passes it as `--target=...`, which zig's target parser rejects. The shim drops
# target flags and selects the equivalent zig spelling, so `CC` can point cc-rs
# at a compiler that understands it. It is written to a temp file and renamed
# into place, so a concurrent run never execs a half-written shim.
shim="$PWD/target/zig-cc-$RUST_TARGET"
mkdir -p "$(dirname "$shim")"
shim_tmp="$(mktemp "$shim.XXXXXX")"
trap 'rm -f "$shim_tmp"' EXIT
cat >"$shim_tmp" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
args=()
skip_value=false
for arg in "$@"; do
  if [[ "$skip_value" == true ]]; then
    skip_value=false
    continue
  fi
  case "$arg" in
  --target=* | -target=*) ;;
  -target) skip_value=true ;;
  *) args+=("$arg") ;;
  esac
done
exec zig cc -target x86_64-windows-gnu ${args[@]+"${args[@]}"}
EOF
chmod +x "$shim_tmp"
mv -f "$shim_tmp" "$shim"
trap - EXIT

if [[ -n "${CC_x86_64_pc_windows_gnu:-}" && "$CC_x86_64_pc_windows_gnu" != "$shim" ]]; then
  echo "note: replacing the configured CC_x86_64_pc_windows_gnu=$CC_x86_64_pc_windows_gnu with the zig shim"
fi
export CC_x86_64_pc_windows_gnu="$shim"

# The guest agent is embedded by the build script in crates/filesystem, so
# build/agentd has to be current; that script says what to run when it is not.

echo "==> cargo check ($RUST_TARGET)"
cargo check --no-default-features --features "$FEATURES" -p "$PACKAGE" --target "$RUST_TARGET"

echo "==> cargo clippy ($RUST_TARGET)"
cargo clippy --no-default-features --features "$FEATURES" -p "$PACKAGE" --target "$RUST_TARGET" -- -D warnings
