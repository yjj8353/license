#!/bin/sh

rm -rf ./target

cargo zigbuild --release -p keygen -p licgen -p licver --target aarch64-apple-darwin
cargo zigbuild --release -p keygen -p licgen -p licver --target x86_64-unknown-linux-gnu
cargo zigbuild --release -p keygen -p licgen -p licver --target x86_64-pc-windows-gnu
# cargo zigbuild --release -p keygen -p licgen -p licver --target aarch64-unknown-linux-gnu