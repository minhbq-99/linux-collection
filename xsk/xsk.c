#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <linux/if_xdp.h>
#include <sys/mman.h>
#include <net/if.h>
#include <stdatomic.h>
#include <stdint.h>
#include <sys/poll.h>
#include <signal.h>
#include <arpa/inet.h>

#include "xsk_bpf.skeleton.h"

#define err_msg(msg) do {perror(msg); exit(1);} while(0)
#define MAX_ENTRIES 256
#define UMEM_CHUNK_SIZE 0x1000
#define INTERFACE "enp0s2"

#define load_acquire(p) \
	atomic_load_explicit((_Atomic typeof(*(p)) *)(p), memory_order_acquire)

#define store_release(p, v) \
	atomic_store_explicit((_Atomic typeof(*(p)) *)(p), v, \
			      memory_order_release)

void signal_handler(int)
{
	bpf_xdp_detach(if_nametoindex(INTERFACE), 0, NULL);
	exit(1);
}

int main()
{
	int sock, num_entries, umem_len, i, ret = 0;
	struct xdp_umem_reg umem_reg = {};
	void *umem_region;
	struct sockaddr_xdp sxdp = {
		.sxdp_family = AF_XDP,
		.sxdp_ifindex = if_nametoindex(INTERFACE),
		.sxdp_queue_id = 0,
		.sxdp_flags = XDP_ZEROCOPY | XDP_USE_SG,
	};
	void *rx_ring, *fill_ring;
	struct xdp_mmap_offsets off;
	int optlen = sizeof(off);
	uint32_t *fq_producer;
	uint32_t *rx_producer, *rx_consumer;
	struct xsk_bpf *bpf;
	struct pollfd fds;
	int key, value;
	uint64_t *addr;

	umem_len = UMEM_CHUNK_SIZE * MAX_ENTRIES;
	umem_region = mmap(0, umem_len, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	if (umem_region == (void *)-1)
		err_msg("mmap umem-region");

	sock = socket(AF_XDP, SOCK_RAW, 0);
	if (sock < 0)
		err_msg("socket");

	/*
	 * This ring is used by the kernel to notify the user space which umem
	 * entry has been filled with rx packets so that user space can read
	 * those packets from it.
	 */
	num_entries = MAX_ENTRIES;
	ret = setsockopt(sock, SOL_XDP, XDP_RX_RING, &num_entries,
			 sizeof(num_entries));
	if (ret < 0)
		err_msg("setsockopt XDP_RX_RING");

	/*
	 * We don't use completion ring as we don't want to use xsk's tx path
	 * (don't want to send packet through xsk) but only xsk's rx path. So
	 * only fill ring is needed but the check in umem creation requires both
	 * completion and fill ring to be set up.
	 */
	num_entries = 2;
	ret = setsockopt(sock, SOL_XDP, XDP_UMEM_COMPLETION_RING, &num_entries,
			 sizeof(num_entries));
	if (ret < 0)
		err_msg("setsockopt XDP_UMEM_COMPLETION_RING");
	
	/*
	 * This ring is used to tell the kernel which umem entry can be used for
	 * rx packets.
	 */
	num_entries = MAX_ENTRIES;
	ret = setsockopt(sock, SOL_XDP, XDP_UMEM_FILL_RING, &num_entries,
			 sizeof(num_entries));
	if (ret < 0)
		err_msg("setsockopt XDP_UMEM_FILL_RING");

	ret = getsockopt(sock, SOL_XDP, XDP_MMAP_OFFSETS, &off, &optlen);
	if (ret < 0)
		err_msg("getsockopt");

	if (optlen != sizeof(off)) {
		fprintf(stderr, "Mismatch sockopt length, exp %ld got %d\n",
			sizeof(off), optlen);
		return 1;
	}

	rx_ring = mmap(0, off.rx.desc + MAX_ENTRIES * sizeof(struct xdp_desc),
		       PROT_READ | PROT_WRITE, MAP_SHARED, sock,
		       XDP_PGOFF_RX_RING);
	if (rx_ring == (void *)-1)
		err_msg("mmap rx-ring");

	fill_ring = mmap(0, off.fr.desc + MAX_ENTRIES * sizeof(uint64_t),
			 PROT_READ | PROT_WRITE, MAP_SHARED, sock,
			 XDP_UMEM_PGOFF_FILL_RING);
	if (fill_ring == (void *)-1)
		err_msg("mmap fill-ring");
	
	umem_reg.addr = (unsigned long long)umem_region;
	umem_reg.len = umem_len;
	umem_reg.chunk_size = UMEM_CHUNK_SIZE;
	ret = setsockopt(sock, SOL_XDP, XDP_UMEM_REG, &umem_reg,
			 sizeof(umem_reg));
	if (ret < 0)
		err_msg("setsockopt XDP_UMEM_REG");

	ret = bind(sock, (const struct sockaddr *)&sxdp, sizeof(sxdp));
	if (ret < 0)
		err_msg("bind");

	/* Submit all umem entries to fill ring */
	addr = fill_ring + off.fr.desc;
	for (i = 0; i < umem_len; i += UMEM_CHUNK_SIZE) {

		*addr = i;
		addr++;
	}
	fq_producer = fill_ring + off.fr.producer;
	store_release(fq_producer, MAX_ENTRIES);

	/* Load and attach xdp program */
	bpf = xsk_bpf__open_and_load();
	if (!bpf) {
		fprintf(stderr, "Failed to load eBPF program\n");
		return 1;
	}

	key = 0;
	value = sock;
	ret = bpf_map__update_elem(bpf->maps.xsk_map, &key, sizeof(key),
				   &value, sizeof(value), 0);
	if (ret < 0)
		err_msg("eBPF map update");

	ret = bpf_xdp_attach(if_nametoindex(INTERFACE),
			     bpf_program__fd(bpf->progs.redirect_xsk), 0, NULL);
	if (ret < 0)
		err_msg("attach eBPF");

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	fds.fd = sock;
	fds.events = POLLIN;
	ret = poll(&fds, 1, -1);
	if (ret < 0) {
		fprintf(stderr, "poll failed, err: %s\n", strerror(errno));
		goto detach_bpf;
	}

	if (fds.revents & POLLIN) {
		uint32_t producer, consumer;
		struct xdp_desc *desc;
		uint64_t offset;

		rx_producer = rx_ring + off.rx.producer;
		rx_consumer = rx_ring + off.rx.consumer;

		producer = load_acquire(rx_producer);
		consumer = load_acquire(rx_consumer);
		printf("Rx ring: producer: %d, consumer: %d\n",
		       producer, consumer);

		desc = rx_ring + off.rx.desc;

		while (consumer < producer) {
			void *data;
			uint16_t len;

			offset = desc[consumer % MAX_ENTRIES].addr;
			printf("Rx ring: Umem offset: 0x%lx\n", offset);

			data = umem_region + offset;

			/*
			 * Ethernet header: 14 bytes
			 * IP header: 16 bytes (no IP options)
			 * UDP header's length offset: 4 bytes
			 */
			data = data + (14 + 20 + 4);
			/*
			 * Subtract the 8 bytes header to get the data's length
			 */
			len = ntohs((*(uint16_t *)data)) - 8;

			/* Data is 4-byte offset from length in UDP packet */
			data = data + 4;

			printf("Received UDP packet: length: %d, data: %.*s\n",
			       len, len, (char *)data);
			consumer++;
		}
		store_release(rx_consumer, consumer);
	} else {
		fprintf(stderr, "Unexpected poll event: %d\n", fds.revents);
		ret = 1;
	}

detach_bpf:
	bpf_xdp_detach(if_nametoindex(INTERFACE), 0, NULL);

	return ret;
}
