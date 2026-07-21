#!/usr/bin/env bash
set -euo pipefail

# 설치전에 항상 해당 머신에 rustup과 zig가 설치되어 있어야 합니다.
TOOLCHAIN="stable"
TARGETS=(
    "aarch64-apple-darwin"
    "x86_64-unknown-linux-gnu"
    "x86_64-pc-windows-gnu"
)

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "ERROR: '$1' not found"
        exit 1
    }
}

ensure_target() {
    local t="$1"
    rustup target list --installed | grep -qx "$t" || rustup target add "$t" --toolchain "$TOOLCHAIN"
}

need_cmd rustup
need_cmd cargo
need_cmd zig

rustup toolchain install "$TOOLCHAIN" --profile minimal
rustup default "$TOOLCHAIN"

if ! cargo zigbuild --version >/dev/null 2>&1; then
    cargo install cargo-zigbuild
fi

for t in "${TARGETS[@]}"; do
    ensure_target "$t"
done

# 필요하면 주석 해제
rm -rf ./target

for t in "${TARGETS[@]}"; do
    cargo +"$TOOLCHAIN" zigbuild --release -p keygen -p licgen -p licver --target "$t"
done