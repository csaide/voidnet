#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Our socket map for redirects, this is filled by the user space application as sockets are registered.
struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 2048); // Having more then 2048 sockets is unlikely to be useful in practice....
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} xsks_map SEC(".maps");

// Per-CPU Array of current round robin indexes, all initialized to 0 and as a per-cpu array we need no synchronization.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(unsigned int));
} rr_map SEC(".maps");

// The total number of sockets registered, this is updated by the user space application as sockets are registered.
unsigned int num_socks = 0;

// The key for the round robin map, this is used to index into the per-CPU array.
static unsigned int rr_key = 0;

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

	// First lookup the current round robin index for the current CPU.
	unsigned int *rr_ptr = (unsigned int *)bpf_map_lookup_elem(&rr_map, &rr_key);
	if (!rr_ptr) {
		return XDP_ABORTED;
	}

	// Increment the round robin index and wrap around if it exceeds the number of sockets. Again this could be faster with a bit mask
	// approach but then we are forced into a power of 2 number of sockets.
	*rr_ptr = (*rr_ptr + 1) % num_socks;

	// Return the redirect to the given rr index, if something goes wrong abort the packet.
	return bpf_redirect_map(&xsks_map, *rr_ptr, XDP_ABORTED);
}
