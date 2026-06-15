/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2021
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
#pragma clang diagnostic ignored "-Warray-bounds"
#pragma clang diagnostic ignored "-Wunused-label"
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"

#include "include/vmlinux.h"
#include "include/vmlinux_missing.h"
#include "bpf/bpf_map.h"
#include "bpf/bpf_helpers.h"

// kubedagger probes
#include "kubedagger/base64.h"
#include "kubedagger/const.h"
#include "kubedagger/defs.h"
#include "kubedagger/hash.h"
#include "kubedagger/process.h"
#include "kubedagger/raw_syscalls.h"
#include "kubedagger/parser.h"
#include "kubedagger/cgroup.h"
#include "kubedagger/http_router.h"
#include "kubedagger/tcp_check.h"
#include "kubedagger/http_action.h"
#include "kubedagger/dns.h"
#include "kubedagger/pipe.h"
#include "kubedagger/fs_watch.h"
#include "kubedagger/fs_action_defs.h"
#include "kubedagger/fs_action_user.h"
#include "kubedagger/docker.h"
#include "kubedagger/postgres.h"
#include "kubedagger/sqli.h"
#include "kubedagger/network_discovery.h"
#include "kubedagger/arp.h"
#include "kubedagger/stat.h"
#include "kubedagger/fs.h"
#include "kubedagger/http_response.h"
#include "kubedagger/bpf.h"
#include "kubedagger/xdp.h"
#include "kubedagger/tc.h"

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
