//go:build ignore

#include "common.h"

#include "bpf_endian.h"
#include "bpf_sockops.h"
#include "bpf_tracing.h"

#define AF_INET 2
#define SOCKOPS_MAP_SIZE 65535

char __license[] SEC("license") = "Dual MIT/GPL";

enum {
	SOCK_TYPE_ACTIVE  = 0,
	SOCK_TYPE_PASSIVE = 1,
};

struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__uint(max_entries, 65535);
	__type(key, struct sock_key);
	__type(value, int);
} sock_ops_map SEC(".maps");

/*
 * extract the key identifying the socket source of the TCP event
 */
static inline void extract_key4_from_ops(struct bpf_sock_ops *ops, struct sock_key *key) {
	// keep ip and port in network byte order
	key->dip4   = ops->remote_ip4;
	key->sip4   = ops->local_ip4;
	key->family = 1;

	// local_port is in host byte order, and
	// remote_port is in network byte order
	key->sport = (bpf_htonl(ops->local_port) >> 16);
	key->dport = FORCE_READ(ops->remote_port) >> 16;
}

/*
 * Insert socket into sockmap
 */
static inline void bpf_sock_ops_ipv4(struct bpf_sock_ops *skops) {
	struct sock_key key = {};
	int ret;

	extract_key4_from_ops(skops, &key);

	if (skops->local_port == 1000 || bpf_ntohl(skops->remote_port) == 1000) {
		ret = bpf_sock_hash_update(skops, &sock_ops_map, &key, BPF_NOEXIST);
		if (ret != 0) {
			printk("sock_hash_update() failed, ret: %d\n", ret);
		}

		printk("sockmap: op %d, port %d --> %d\n", skops->op, skops->local_port, bpf_ntohl(skops->remote_port));
	}
}

SEC("sockops")
int bpf_sockops_cb(struct bpf_sock_ops *skops) {
	u32 op;
	op = skops->op;

	switch (op) {
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		if (skops->family == 2) {
			// AF_INET
			bpf_sock_ops_ipv4(skops);
		}
		break;
	default:
		break;
	}

	return 0;
}

/*
 * extract the key that identifies the destination socket in the sock_ops_map
 */
static inline void extract_key4_from_msg(struct sk_msg_md *msg, struct sock_key *key) {
	key->sip4   = msg->remote_ip4;
	key->dip4   = msg->local_ip4;
	key->family = 1;

	key->dport = (bpf_htonl(msg->local_port) >> 16);
	key->sport = FORCE_READ(msg->remote_port) >> 16;
}

SEC("sk_msg")
int bpf_redir(struct sk_msg_md *msg) {
	printk("bpf_redir is being called");
	struct sock_key key = {};
	extract_key4_from_msg(msg, &key);
	printk("bpf_redir before bpf_msg_redirect_hash being called");
	long ret = bpf_msg_redirect_hash(msg, &sock_ops_map, &key, BPF_F_INGRESS);
	printk("ret is %, redirect % bytes with eBPF successfully", ret, msg->size);

	return SK_PASS;
}