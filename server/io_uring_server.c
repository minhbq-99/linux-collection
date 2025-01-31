/* Echo server with vanilla io_uring without using liburing */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/syscall.h>
#include <linux/io_uring.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <stdatomic.h>
#include <sys/syscall.h>
#include <stdint.h>

#define err_msg(msg) fprintf(stderr, msg ": %s\n", strerror(errno))

#define HOST "0.0.0.0"
#define PORT 8888
#define BACKLOG 512

#define MAX_SQE 8192
#define MAX_BUFFER 32768

#define load_acquire(p) \
	atomic_load_explicit((_Atomic typeof(*(p)) *)(p), memory_order_acquire)

#define store_release(p, v) \
	atomic_store_explicit((_Atomic typeof(*(p)) *)(p), v, memory_order_release)

/*
 * We use this struct user_data when submitting io_uring
 * entry to have the information when receiving completion
 * entry.
 *
 * The most significant bits of buffer are used to store
 * action information. In case the action is ACT_RECV/
 * ACT_SEND, the buffer points to struct sock_ctrl to store
 * information about file descriptor and received/sent buffer.
 */
struct packed_pointer {
	unsigned long long buffer;
};

enum action {
	ACT_ACCEPT,
	ACT_RECV,
	ACT_SEND,
};

/*
 * 2 most significant bits of packed_pointer->buffer
 * are used to store action.
 */
#define ACTION_SHIFT 62
#define POINTER_MASK ~(3ULL << ACTION_SHIFT)

void set_action(struct packed_pointer *ptr, enum action act)
{
	ptr->buffer = ptr->buffer | ((unsigned long long)act << ACTION_SHIFT);
}

enum action get_action(struct packed_pointer *ptr)
{
	return (enum action)(ptr->buffer >> ACTION_SHIFT);
}

void* get_raw_buffer(struct packed_pointer *ptr)
{
	return (void *)(ptr->buffer & POINTER_MASK);
}

struct sock_ctrl {
	int fd;
	char *buffer;
};

struct io_uring_ctrl {
	int io_uring_offset;
	struct io_uring_params *params;
};

int setup_listen_sock()
{
	int listen_sock, sockopt, ret;
	struct sockaddr_in saddr = {
		.sin_family = AF_INET,
		.sin_addr = inet_addr(HOST),
		.sin_port = htons(PORT),
	};

	listen_sock = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_sock < 0) {
		err_msg("failed to create socket");
		return -1;
	}

	sockopt = 1;
	ret = setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &sockopt,
			 sizeof(sockopt));
	if (ret < 0) {
		err_msg("failed to setsockopt");
		return -1;
	}

	ret = bind(listen_sock, (struct sockaddr *)&saddr, sizeof(saddr));
	if (ret < 0) {
		err_msg("failed to bind socket");
		return -1;
	}

	ret = listen(listen_sock, BACKLOG);
	if (ret < 0) {
		err_msg("failed to listen socket");
		return -1;
	}

	printf("Server socket is listening on %s:%d\n", HOST, PORT);

	return listen_sock;
}

struct io_uring_ctrl *setup_io_uring()
{
	int io_uring_fd, ret;
	struct io_uring_params *params;
	void *cq_ring, *sqe_ring;
	unsigned cq_ring_size, sqe_ring_size;
	struct io_uring_rsrc_update reg = {};
	struct io_uring_ctrl *ctrl;

	ctrl = malloc(sizeof(struct io_uring_ctrl));
	if (!ctrl) {
		fprintf(stderr, "failed to malloc\n");
		return NULL;
	}

	params = calloc(1, sizeof(struct io_uring_params));
	if (!params) {
		fprintf(stderr, "failed to malloc\n");
		goto free_ctrl;
	}
	ctrl->params = params;

	params->flags = IORING_SETUP_NO_SQARRAY;

	io_uring_fd = syscall(SYS_io_uring_setup, MAX_SQE, params);
	if (io_uring_fd < 0) {
		err_msg("failed to setup io_uring");
		goto free_params;
	}

	reg.data = io_uring_fd;
	reg.offset = -1;
	ret = syscall(SYS_io_uring_register, io_uring_fd,
		      IORING_REGISTER_RING_FDS, &reg, 1);
	if (ret < 0) {
		err_msg("failed to register io_uring fd to ring");
		goto close_io_uring;
	}
	ctrl->io_uring_offset = reg.offset;

	printf("io_uring fd registered offset: %d\n"
	       "cq_entries: %d\n"
	       "sq_entries: %d\n",
	       ctrl->io_uring_offset, params->cq_entries, params->sq_entries);

	cq_ring_size = params->cq_entries * sizeof(struct io_uring_cqe);
	/*
	 * Align up to PAGE_SIZE and add 1 additional page for
	 * struct io_rings.
	 */
	cq_ring_size = (cq_ring_size + 0x1000) & ~(0x1000U - 1);
	cq_ring = mmap(0, cq_ring_size, PROT_READ | PROT_WRITE,
		       MAP_SHARED | MAP_FILE, io_uring_fd,
		       IORING_OFF_CQ_RING);
	if (cq_ring == (void *)-1) {
		err_msg("failed to mmap cq_ring");
		goto close_io_uring;
	}

	sqe_ring_size = params->sq_entries * sizeof(struct io_uring_sqe);
	sqe_ring_size = (sqe_ring_size + (0x1000 - 1)) & ~(0x1000U - 1);
	sqe_ring = mmap(0, sqe_ring_size, PROT_READ | PROT_WRITE,
		        MAP_SHARED | MAP_FILE, io_uring_fd, IORING_OFF_SQES);
	if (sqe_ring == (void *)-1) {
		err_msg("failed to mmap sqe_ring");
		goto unmap_cq_ring;
	}
	params->cq_off.user_addr = (unsigned long long)cq_ring;
	params->sq_off.user_addr = (unsigned long long)sqe_ring;

	return ctrl;

unmap_cq_ring:
	munmap(cq_ring, cq_ring_size);
close_io_uring:
	close(io_uring_fd);
free_params:
	free(params);
free_ctrl:
	free(ctrl);
	return NULL;
}

void submit_sqe(struct io_uring_ctrl *ctrl, struct io_uring_sqe *sqe)
{
	struct io_sqring_offsets *sq_off = &ctrl->params->sq_off;
	struct io_uring_sqe *sqe_arr = (void *)sq_off->user_addr;
	void *io_uring = (void *)ctrl->params->cq_off.user_addr;
	unsigned int *sq_ring_tail_ptr = io_uring + sq_off->tail;
	unsigned int tail = *sq_ring_tail_ptr;
	unsigned int mask = *((unsigned int *)(io_uring + sq_off->ring_mask));
	int ret;

	sqe_arr[tail & mask] = *sqe;
	store_release(sq_ring_tail_ptr, tail + 1);
}

int flush_all_sqes(struct io_uring_ctrl *ctrl, int num_entries)
{
	int ret;

	ret = syscall(SYS_io_uring_enter, ctrl->io_uring_offset,
		      num_entries, 0, IORING_ENTER_REGISTERED_RING,
		      NULL, 0);
	if (ret < 0) {
		err_msg("failed to submit new sqe");
		return -1;
	}
	return 0;
}

void clean_up_sock(struct sock_ctrl *sctrl)
{
	free(sctrl->buffer);
	close(sctrl->fd);
	free(sctrl);
}

int handle_completion_event(struct io_uring_ctrl *ctrl, unsigned int head,
			    unsigned int tail, unsigned int mask)
{
	struct io_cqring_offsets *cq_off = &ctrl->params->cq_off;
	void *io_uring = (void *)cq_off->user_addr;
	struct io_uring_cqe *cqe_arr = io_uring + cq_off->cqes;
	enum action act;
	char *buffer;
	struct sock_ctrl *sctrl;
	struct io_uring_cqe *cqe;
	int ret;
	unsigned int orig_head = head;

	while (head != tail) {
		struct io_uring_sqe sqe = {};
		struct packed_pointer ptr;

		cqe = &cqe_arr[head & mask];
		ptr.buffer = cqe->user_data;
		act = get_action(&ptr);
		switch (act) {
		case ACT_ACCEPT:
			if (cqe->res < 0) {
				fprintf(stderr,
					"failed to accept socket: %s\n",
					strerror(cqe->res));
				break;
			}

			sctrl = malloc(sizeof(struct sock_ctrl));
			if (!sctrl) {
				fprintf(stderr,
					"failed to allocate socket control\n");
				return -1;
			}

			buffer = malloc(MAX_BUFFER);
			if (!buffer) {
				fprintf(stderr, "failed to allocate buffer\n");
				return -1;
			}
			sctrl->fd = cqe->res;
			sctrl->buffer = buffer;

			sqe.opcode = IORING_OP_RECV;
			sqe.fd = cqe->res;
			sqe.addr = (unsigned long long)buffer;
			sqe.len = MAX_BUFFER;

			ptr.buffer = (unsigned long long)sctrl;
			set_action(&ptr, ACT_RECV);
			sqe.user_data = ptr.buffer;

			submit_sqe(ctrl, &sqe);
			break;
		case ACT_RECV:
			sctrl = get_raw_buffer(&ptr);

			if (cqe->res <= 0) {
				if (cqe->res < 0)
					fprintf(stderr,
						"failed to receive socket: %s\n",
						strerror(-cqe->res));

				clean_up_sock(sctrl);
				break;
			}

			sqe.opcode = IORING_OP_SEND;
			sqe.fd = sctrl->fd;
			sqe.addr = (unsigned long long)sctrl->buffer;
			sqe.len = cqe->res;

			ptr.buffer = (unsigned long long)sctrl;
			set_action(&ptr, ACT_SEND);
			sqe.user_data = ptr.buffer;

			submit_sqe(ctrl, &sqe);
			break;
		case ACT_SEND:
			sctrl = get_raw_buffer(&ptr);

			if (cqe->res < 0) {
				fprintf(stderr,
					"failed to send socket: %s\n",
					strerror(-cqe->res));
				clean_up_sock(sctrl);
				break;
			}

			sqe.opcode = IORING_OP_RECV;
			sqe.fd = sctrl->fd;
			sqe.addr = (unsigned long long)buffer;
			sqe.len = MAX_BUFFER;

			ptr.buffer = (unsigned long long)sctrl;
			set_action(&ptr, ACT_RECV);
			sqe.user_data = ptr.buffer;

			submit_sqe(ctrl, &sqe);
			break;
		}

		head++;
	}

	return flush_all_sqes(ctrl, tail - orig_head);
}

int monitor_completion_queue(struct io_uring_ctrl *ctrl)
{
	struct io_cqring_offsets *cq_off = &ctrl->params->cq_off;
	void *io_uring = (void *)cq_off->user_addr;
	struct io_uring_cqe *cqe_arr = io_uring + cq_off->cqes;
	unsigned int *cq_ring_tail_ptr = io_uring + cq_off->tail;
	unsigned int *cq_ring_head_ptr = io_uring + cq_off->head;
	struct io_uring_cqe *cqe;
	unsigned int tail, head;
	unsigned int mask = *((unsigned int *)(io_uring + cq_off->ring_mask));
	int i = 0, ret;

	head = *cq_ring_head_ptr;

	while (1) {
		do {
			tail = load_acquire(cq_ring_tail_ptr);
			i++;
		} while (head == tail && i < 1000);

		if (head == tail) {
			ret = syscall(SYS_io_uring_enter, ctrl->io_uring_offset, 0, 1,
				IORING_ENTER_REGISTERED_RING | IORING_ENTER_GETEVENTS,
				NULL, 0);
			if (ret < 0) {
				err_msg("failed to wait for completion");
				return -1;
			}
			tail = load_acquire(cq_ring_tail_ptr);
		}

		ret = handle_completion_event(ctrl, head, tail, mask);
		if (ret < 0) {
			fprintf(stderr, "failed to handle completion event\n");
			return -1;
		}
		head = tail;
		store_release(cq_ring_head_ptr, head);
	}

	return 0;
}

int main()
{
	int ret, listen_sock;
	struct io_uring_ctrl *ctrl;
	struct io_uring_sqe sqe = {};
	struct packed_pointer ptr;

	listen_sock = setup_listen_sock();
	if (listen_sock < 0) {
		fprintf(stderr, "failed to setup listen socket\n");
		return 1;
	}
	
	ctrl = setup_io_uring();
	if (!ctrl) {
		fprintf(stderr, "failed to setup io_uring\n");
		return 1;
	}

	set_action(&ptr, ACT_ACCEPT);
	sqe.fd = listen_sock;
	sqe.opcode = IORING_OP_ACCEPT;
	sqe.ioprio = IORING_ACCEPT_MULTISHOT;
	sqe.user_data = ptr.buffer;
	submit_sqe(ctrl, &sqe);
	ret = flush_all_sqes(ctrl, 1);
	if (ret < 0) {
		fprintf(stderr, "failed to submit accept sock\n");
		return 1;
	}

	ret = monitor_completion_queue(ctrl);
	if (ret < 0) {
		fprintf(stderr, "failed to monitor completion queue\n");
		return 1;
	}

	return 0;
}
