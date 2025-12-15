#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, MAX_SOCKS);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} xsks_map SEC(".maps");

// We do a simple RR across all registered sockets.
unsigned int num_socks = 0;
static unsigned int rr;

SEC("xdp_sock") int xdp_sock_prog(struct xdp_md *ctx) {
	// Wrapping RR algo.
	rr = (rr + 1) & (num_socks - 1);
	return bpf_redirect_map(&xsks_map, rr, XDP_DROP);
}
