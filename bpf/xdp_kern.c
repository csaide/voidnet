#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 2048); // Having more then 2048 sockets is unlikely to be useful in practice....
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} xsks_map SEC(".maps");

unsigned int num_socks = 0;
static unsigned int rr;

SEC("xdp_sock") int xdp_sock_prog(struct xdp_md *ctx) {
	// We don't have any user space sockets to hand off traffic to, so just pass it off to the kernel.
	if (num_socks == 0) {
		return XDP_PASS;
	}
	
	// We have exactly one user space socket, so fast path directly into the redirect map.
	if (num_socks == 1) {
		return bpf_redirect_map(&xsks_map, 0, XDP_ABORTED);
	}

	// Wrapping RR algo, this is inefficient but flexible and means we can have any number of sockets,
	// a potentially "faster" approach would be to use bit masking and force power of 2 num sockets.
	//
	// Testing has proven this to be more than efficent enough for this use case as the I/O operations themselves
	// dwarf these extra division operations.
	rr = (rr + 1) % num_socks;

	// Return the redirect to the given rr index, if something goes wrong abort the packet.
	return bpf_redirect_map(&xsks_map, rr, XDP_ABORTED);
}
