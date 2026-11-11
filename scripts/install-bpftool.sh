#!/usr/bin/env bash
# Install a fixed bpftool revision; its libbpf submodule is pinned by Git too.
set -euo pipefail

revision=d844a27fc175aeae3bcb29b052813ef210c97004 # v7.5.0
build_dir=$(mktemp -d)
trap 'rm -rf "$build_dir"' EXIT
git init "$build_dir"
git -C "$build_dir" remote add origin https://github.com/libbpf/bpftool.git
git -C "$build_dir" fetch --depth 1 origin "$revision"
git -C "$build_dir" checkout --detach FETCH_HEAD
git -C "$build_dir" submodule update --init --recursive --depth 1
make -C "$build_dir/src" -j"$(nproc)"
make -C "$build_dir/src" install
