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
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, SOCKOPS_MAP_SIZE);
	__type(key, struct sk_key);
	__type(value, struct sk_info);
} map_estab_sk SEC(".maps");

// key的信息
struct sk_key {
	u32 local_ip4;
	u32 remote_ip4;
	u32 local_port;
	u32 remote_port;
};

// value的信息
struct sk_info {
	struct sk_key sk_key;
	u8 sk_type;
};

// 记录rtt events的map
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} rtt_events SEC(".maps");

struct rtt_event {
	u16 sport;
	u16 dport;
	u32 saddr;
	u32 daddr;
	u32 srtt;
};
struct rtt_event *unused_event __attribute__((unused));

static inline void init_sk_key(struct bpf_sock_ops *skops, struct sk_key *sk_key) {
	sk_key->local_ip4   = bpf_ntohl(skops->local_ip4);
	sk_key->remote_ip4  = bpf_ntohl(skops->remote_ip4);
	sk_key->local_port  = skops->local_port;
	sk_key->remote_port = bpf_ntohl(skops->remote_port);
}

static inline void bpf_sock_ops_establish_cb(struct bpf_sock_ops *skops, u8 sock_type) {
	int err;
	struct sk_info sk_info = {};
	// Only process IPv4 sockets
	// 只处理IPv4的sockets
	if (skops == NULL || skops->family != AF_INET)
		return;

	// Initialize the 4-tuple key
	// 初始化4元组的key
	init_sk_key(skops, &sk_info.sk_key);
	sk_info.sk_type = sock_type;

	// Store the socket info in map using the 4-tuple as key
	// We keep track of TCP connections in 'established' state
	// 存储socket info到map，使用4-tuple作为key，我们追踪处于"established"状态的TCP connections
	err = bpf_map_update_elem(&map_estab_sk, &sk_info.sk_key, &sk_info, BPF_NOEXIST);
	if (err != 0) {
		// Storing the 4-tuple in map has failed, return early.
		// 在Map中存储4-tuple失败，尽早返回
		// This can happen in case the 4-tuple already exists in the map (i.e. BPF_NOEXIST flag)
		// 这可能在4-tuple已经在map中存在时发生
		return;
	}

	// Enable sockops callbacks for RTT and TCP state change
	// 使能sockops callbacks，对于RTT以及TCP state change
	bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_RTT_CB_FLAG | BPF_SOCK_OPS_STATE_CB_FLAG);
}

static inline void bpf_sock_ops_rtt_cb(struct bpf_sock_ops *skops) {
	struct sk_key sk_key = {};
	struct sk_info *sk_info;
	struct rtt_event *rtt_event;

	// Initialize the 4-tuple key
	// 初始化4-tuple的key
	init_sk_key(skops, &sk_key);

	// Retrieve the socket info from map of established connections
	// 从建立的连接的map中抽取出socket info
	sk_info = bpf_map_lookup_elem(&map_estab_sk, &sk_key);
	if (!sk_info)
		return;

	rtt_event = bpf_ringbuf_reserve(&rtt_events, sizeof(struct rtt_event), 0);
	if (!rtt_event) {
		return;
	}

	switch (sk_info->sk_type) {
	case SOCK_TYPE_ACTIVE:
		// If socket is 'active', 'local' means 'source'
		// and 'remote' means 'destination'
		// 如果socket是'active', 'local'意味着'source'
		// 并且'remote'意味着'destination'
		rtt_event->saddr = sk_info->sk_key.local_ip4;
		rtt_event->daddr = sk_info->sk_key.remote_ip4;
		rtt_event->sport = sk_info->sk_key.local_port;
		rtt_event->dport = sk_info->sk_key.remote_port;
		break;
	case SOCK_TYPE_PASSIVE:
		// If socket is 'passive', 'local' means 'destination'
		// and 'remote' means 'source'
		// 如果socket是'passive', 'local'意味着'destination', 'remote'意味着'source'
		rtt_event->saddr = sk_info->sk_key.remote_ip4;
		rtt_event->daddr = sk_info->sk_key.local_ip4;
		rtt_event->sport = sk_info->sk_key.remote_port;
		rtt_event->dport = sk_info->sk_key.local_port;
		break;
	}

	// Extract smoothed RTT
	// 抽取smoothed RTT
	rtt_event->srtt = skops->srtt_us >> 3;
	rtt_event->srtt /= 1000;

	// Send RTT event data to userspace app via ring buffer
	// 发送RTT event data到用户空间的app，通过ring buffer
	bpf_ringbuf_submit(rtt_event, 0);
}

static inline void bpf_sock_ops_state_cb(struct bpf_sock_ops *skops) {
	struct sk_key sk_key = {};

	// Socket changed state. args[0] stores the previous state.
	// Perform cleanup of map entry if socket is exiting
	// the 'established' state,
	// socket改变了state, args[0]存储了之前的state，执行map entry的cleanup，如果socket跳出了
	// 'established'状态
	if (skops->args[0] == TCP_ESTABLISHED) {
		init_sk_key(skops, &sk_key);
		// 删除map
		bpf_map_delete_elem(&map_estab_sk, &sk_key);
	}
}

SEC("sockops")
int bpf_sockops_cb(struct bpf_sock_ops *skops) {
	u32 op;
	op = skops->op;

	switch (op) {
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		bpf_sock_ops_establish_cb(skops, SOCK_TYPE_ACTIVE);
		break;
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		bpf_sock_ops_establish_cb(skops, SOCK_TYPE_PASSIVE);
		break;
	case BPF_SOCK_OPS_RTT_CB:
		bpf_sock_ops_rtt_cb(skops);
		break;
	case BPF_SOCK_OPS_STATE_CB:
		bpf_sock_ops_state_cb(skops);
		break;
	}

	return 0;
}
