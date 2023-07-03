/*
 * Note that this header file contains a subset of kernel
 * definitions needed for the tcprtt_sockops example.
 */
#ifndef BPF_SOCKOPS_H
#define BPF_SOCKOPS_H

/*
 * Copy of TCP states.
 * See: https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/bpf.h#L6347.
 */
enum {
	TCP_ESTABLISHED  = 1,
	TCP_SYN_SENT     = 2,
	TCP_SYN_RECV     = 3,
	TCP_FIN_WAIT1    = 4,
	TCP_FIN_WAIT2    = 5,
	TCP_TIME_WAIT    = 6,
	TCP_CLOSE        = 7,
	TCP_CLOSE_WAIT   = 8,
	TCP_LAST_ACK     = 9,
	TCP_LISTEN       = 10,
	TCP_CLOSING      = 11,
	TCP_NEW_SYN_RECV = 12,
	TCP_MAX_STATES   = 13,
};

/*
 * Copy of sock_ops operations.
 * See: https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/bpf.h#L6233.
 */
enum {
	BPF_SOCK_OPS_VOID                   = 0,
	BPF_SOCK_OPS_TIMEOUT_INIT           = 1,
	BPF_SOCK_OPS_RWND_INIT              = 2,
	BPF_SOCK_OPS_TCP_CONNECT_CB         = 3,
	BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB  = 4,
	BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB = 5,
	BPF_SOCK_OPS_NEEDS_ECN              = 6,
	BPF_SOCK_OPS_BASE_RTT               = 7,
	BPF_SOCK_OPS_RTO_CB                 = 8,
	BPF_SOCK_OPS_RETRANS_CB             = 9,
	BPF_SOCK_OPS_STATE_CB               = 10,
	BPF_SOCK_OPS_TCP_LISTEN_CB          = 11,
	BPF_SOCK_OPS_RTT_CB                 = 12,
	BPF_SOCK_OPS_PARSE_HDR_OPT_CB       = 13,
	BPF_SOCK_OPS_HDR_OPT_LEN_CB         = 14,
	BPF_SOCK_OPS_WRITE_HDR_OPT_CB       = 15,
};

/*
 * Copy of definitions for bpf_sock_ops_cb_flags.
 * See: https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/bpf.h#L6178.
 */
enum {
	BPF_SOCK_OPS_RTO_CB_FLAG                   = 1,
	BPF_SOCK_OPS_RETRANS_CB_FLAG               = 2,
	BPF_SOCK_OPS_STATE_CB_FLAG                 = 4,
	BPF_SOCK_OPS_RTT_CB_FLAG                   = 8,
	BPF_SOCK_OPS_PARSE_ALL_HDR_OPT_CB_FLAG     = 16,
	BPF_SOCK_OPS_PARSE_UNKNOWN_HDR_OPT_CB_FLAG = 32,
	BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG         = 64,
	BPF_SOCK_OPS_ALL_CB_FLAGS                  = 127,
};

/*
 * Copy of bpf.h's bpf_sock_ops with minimal subset
 * of fields used by the tcprtt_sockops example.
 * See: https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/bpf.h#L6101.
 */
struct bpf_sock_ops {
	__u32 op;
	union {
		__u32 args[4];
		__u32 reply;
		__u32 replylong[4];
	};
	__u32 family;
	__u32 remote_ip4;
	__u32 local_ip4;
	__u32 remote_port;
	__u32 local_port;
	__u32 srtt_us;
	__u32 bpf_sock_ops_cb_flags;
} __attribute__((preserve_access_index));

#ifndef FORCE_READ
#define FORCE_READ(X) (*(volatile typeof(X) *)&X)
#endif

#ifdef PRINTNL
#define PRINT_SUFFIX "\n"
#else
#define PRINT_SUFFIX ""
#endif

#ifndef printk
#define printk(fmt, ...) \
	({ \
		char ____fmt[] = fmt PRINT_SUFFIX; \
		bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
	})
#endif

struct sock_key {
	__u32 sip4;
	__u32 dip4;
	__u8 family;
	__u8 pad1;  // this padding required for 64bit alignment
	__u16 pad2; // else ebpf kernel verifier rejects loading of the program
	__u32 pad3;
	__u32 sport;
	__u32 dport;
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__uint(max_entries, 65535);
	__type(key, struct sock_key);
	__type(value, int);
} sock_ops_map SEC(".maps");

#define __bpf_md_ptr(type, name) \
	union { \
		type name; \
		__u64 : 64; \
	} __attribute__((aligned(8)))

struct bpf_sock {
	__u32 bound_dev_if;
	__u32 family;
	__u32 type;
	__u32 protocol;
	__u32 mark;
	__u32 priority;
	/* IP address also allows 1 and 2 bytes access */
	__u32 src_ip4;
	__u32 src_ip6[4];
	__u32 src_port;  /* host byte order */
	__be16 dst_port; /* network byte order */
	__u16 : 16;      /* zero padding */
	__u32 dst_ip4;
	__u32 dst_ip6[4];
	__u32 state;
	__s32 rx_queue_mapping;
};

/* user accessible metadata for SK_MSG packet hook, new fields must
 * be added to the end of this structure
 */
struct sk_msg_md {
	__bpf_md_ptr(void *, data);
	__bpf_md_ptr(void *, data_end);

	__u32 family;
	__u32 remote_ip4;    /* Stored in network byte order */
	__u32 local_ip4;     /* Stored in network byte order */
	__u32 remote_ip6[4]; /* Stored in network byte order */
	__u32 local_ip6[4];  /* Stored in network byte order */
	__u32 remote_port;   /* Stored in network byte order */
	__u32 local_port;    /* stored in host byte order */
	__u32 size;          /* Total size of sk_msg */

	__bpf_md_ptr(struct bpf_sock *, sk); /* current socket */
};

/* BPF_FUNC_clone_redirect and BPF_FUNC_redirect flags. */
enum {
	BPF_F_INGRESS = (1ULL << 0),
};

enum sk_action {
	SK_DROP = 0,
	SK_PASS,
};

#endif