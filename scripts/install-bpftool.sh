#!/usr/bin/env bash
# Install a fixed bpftool revision; its libbpf submodule is pinned by Git too.
set -euo pipefail

# v7.8.1 includes libbpf's C23 const-correctness fixes for GCC 15+/glibc 2.42+.
revision=0711105b503c2fd37ac7a219163fb488b3b59d88 # v7.8.1
build_dir=$(mktemp -d)
trap 'rm -rf "$build_dir"' EXIT
git init "$build_dir"
git -C "$build_dir" remote add origin https://github.com/libbpf/bpftool.git
git -C "$build_dir" fetch --depth 1 origin "$revision"
git -C "$build_dir" checkout --detach FETCH_HEAD
git -C "$build_dir" submodule update --init --recursive --depth 1
make -C "$build_dir/src" -j"$(nproc)"
make -C "$build_dir/src" install
