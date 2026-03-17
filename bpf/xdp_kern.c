#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

// Socket map for redirects, filled by userspace as sockets are registered.
// Indexed by queue ID (sparse — gaps are allowed for unbound queues).
struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 2048);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} xsks_map SEC(".maps");

// Route packets from hardware queue N to socket N.
// If no socket is registered for this queue, XDP_PASS hands the packet to the kernel stack.
SEC("xdp_sock") int xdp_sock_prog(struct xdp_md *ctx) {
	return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);
}
