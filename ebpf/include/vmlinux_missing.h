#ifndef __VMLINUX_MISSING_H__
#define __VMLINUX_MISSING_H__

/*
 * Constants not available in vmlinux.h (which only contains type/enum
 * definitions from BTF, not preprocessor #defines from kernel headers).
 */

/* BPF map update flags — from <uapi/linux/bpf.h> */
#define BPF_ANY       0
#define BPF_NOEXIST   1
#define BPF_EXIST     2
#define BPF_F_LOCK    4

/* BPF map creation flags */
#define BPF_F_NO_PREALLOC (1U << 0)

/* BPF checksum flags */
#define BPF_F_RECOMPUTE_CSUM (1ULL << 0)

/* Ethernet — from <uapi/linux/if_ether.h> */
#define ETH_P_IP    0x0800
#define ETH_P_ARP   0x0806
#define ETH_P_IPV6  0x86DD
#define ETH_HLEN    14

/* ARP — from <uapi/linux/if_arp.h> */
#define ARPHRD_ETHER 1
#define ARPOP_REPLY  2

/* TC action verdicts — from <uapi/linux/pkt_cls.h> */
#define TC_ACT_OK         0
#define TC_ACT_RECLASSIFY 1
#define TC_ACT_SHOT       2
#define TC_ACT_PIPE       3
#define TC_ACT_STOLEN     4
#define TC_ACT_REDIRECT   7

/* Byte-order helpers using compiler builtins */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define __bpf_ntohs(x) __builtin_bswap16(x)
#define __bpf_htons(x) __builtin_bswap16(x)
#define __bpf_ntohl(x) __builtin_bswap32(x)
#define __bpf_htonl(x) __builtin_bswap32(x)
#else
#define __bpf_ntohs(x) (x)
#define __bpf_htons(x) (x)
#define __bpf_ntohl(x) (x)
#define __bpf_htonl(x) (x)
#endif

#define bpf_ntohs(x) \
    (__builtin_constant_p(x) ? \
        ((__u16)((((__u16)(x) & 0x00ffU) << 8) | \
                 (((__u16)(x) & 0xff00U) >> 8))) : \
        __bpf_ntohs(x))
#define bpf_htons(x) \
    (__builtin_constant_p(x) ? \
        ((__u16)((((__u16)(x) & 0x00ffU) << 8) | \
                 (((__u16)(x) & 0xff00U) >> 8))) : \
        __bpf_htons(x))
#define bpf_ntohl(x) \
    (__builtin_constant_p(x) ? \
        ((__u32)((((__u32)(x) & 0x000000ffU) << 24) | \
                 (((__u32)(x) & 0x0000ff00U) <<  8) | \
                 (((__u32)(x) & 0x00ff0000U) >>  8) | \
                 (((__u32)(x) & 0xff000000U) >> 24))) : \
        __bpf_ntohl(x))
#define bpf_htonl(x) \
    (__builtin_constant_p(x) ? \
        ((__u32)((((__u32)(x) & 0x000000ffU) << 24) | \
                 (((__u32)(x) & 0x0000ff00U) <<  8) | \
                 (((__u32)(x) & 0x00ff0000U) >>  8) | \
                 (((__u32)(x) & 0xff000000U) >> 24))) : \
        __bpf_htonl(x))

#define htons(x) bpf_htons(x)
#define ntohs(x) bpf_ntohs(x)
#define htonl(x) bpf_htonl(x)
#define ntohl(x) bpf_ntohl(x)

#endif /* __VMLINUX_MISSING_H__ */
