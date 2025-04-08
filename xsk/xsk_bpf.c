#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/in.h>

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} xsk_map SEC(".maps");

/*
 * A normal bpf function has the signature int(void*).
 * We cannot directly access xdp_buff from xdp eBPF but
 * must access from xdp_md struct. The access will be
 * converted by xdp_convert_ctx_access().
 *
 * Redirect UDP packets to XDP socket.
 */
SEC("xdp")
int redirect_xsk(struct xdp_md *xdp)
{
	__u32 key = 0;
	/* EtherType offset in Ethernet frame */
	unsigned int offset = 12;
	__u16 ether_type;
	__u8 protocol;
	int err;

	err = bpf_xdp_load_bytes(xdp, offset, &ether_type, sizeof(ether_type));
	if (err)
		return XDP_PASS;

	if (bpf_ntohs(ether_type) != ETH_P_IP)
		return XDP_PASS;

	/* Ethernet header: 14 bytes, protocol offset: 9 bytes */
	offset = 23;
	err = bpf_xdp_load_bytes(xdp, offset, &protocol, sizeof(protocol));
	if (err)
		return XDP_PASS;

	if (protocol != IPPROTO_UDP)
		return XDP_PASS;

	/* return XDP_DROP on failure */
	return bpf_redirect_map(&xsk_map, key, XDP_DROP);
}

char _license[] SEC("license") = "GPL v2";
