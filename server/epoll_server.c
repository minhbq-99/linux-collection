#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <sys/time.h>

#define err_exit(msg) do {perror(msg); exit(1);} while(0)
#define err_msg(msg) fprintf(stderr, msg ": %s\n", strerror(errno))

#define HOST "0.0.0.0"
#define PORT 8888
#define BACKLOG 512

#define MAX_SOCKETS 8192
#define MAX_EVENTS 512
#define MAX_BUFFER 32768

#define load_acquire(p) \
	atomic_load_explicit((_Atomic typeof(*(p)) *)(p), memory_order_acquire)

#define store_release(p, v) \
	atomic_store_explicit((_Atomic typeof(*(p)) *)(p) , v, memory_order_release)

int num_of_cpus;
int sock_queue_size;

struct thread_data {
	struct work_queue *wq;
	int epoll_fd;
};

struct work_queue {
	int *sock;
	int head;
	int tail;
};

int is_wq_empty(struct work_queue *wq)
{
	/*
	 * Synchronizes with the store_release in enqueue_work.
	 * The read to wq->head does need to have any
	 * synchronization as the write to wq->head happens in
	 * the same thread.
	 */
	int tail = load_acquire(&wq->tail);

	return wq->head == tail;
}

int is_wq_full(struct work_queue *wq)
{
	/*
	 * Synchronizes with the store_release in pop_work
	 * The read to wq->tail does need to have any
	 * synchronization as the write to wq->tail happens in
	 * the same thread.
	 */
	int head = load_acquire(&wq->head);

	return (wq->tail + 1) % sock_queue_size == head;
}

void enqueue_work(struct work_queue *wq, int sock)
{
	int new_tail;

	/*
	 * TODO: This burns the CPU but ensures low latency.
	 * Can we do better with futex?
	 */
	while (is_wq_full(wq));

	wq->sock[wq->tail] = sock;
	new_tail = (wq->tail + 1) % sock_queue_size;
	store_release(&wq->tail, new_tail);
}

int pop_work(struct work_queue *wq)
{
	int new_head, sock;

	/*
	 * TODO: This burns the CPU but ensures low latency.
	 * Can we do better with futex?
	 */
	while (is_wq_empty(wq));

	sock = wq->sock[wq->head];
	new_head = (wq->head + 1) % sock_queue_size;
	store_release(&wq->head, new_head);
	return sock;
}

void free_work_queue_list(struct work_queue *work_queue_list, int count)
{
	int i;

	for (i = 0; i < count; i++)
		free(work_queue_list[i].sock);

	free(work_queue_list);
}

/* Allocate a work queue for each CPU */
struct work_queue *setup_work_queue_list(int num_of_cpus)
{
	int i, j;
	struct work_queue *work_queue_list;

	work_queue_list = malloc(num_of_cpus * sizeof(struct work_queue));
	if (!work_queue_list) {
		fprintf(stderr, "failed to malloc worker_list\n");
		return NULL;
	}

	for (i = 0; i < num_of_cpus; i++) {
		work_queue_list[i].head = work_queue_list[i].tail = 0;
		work_queue_list[i].sock = malloc(sizeof(int) * sock_queue_size);
		if (!work_queue_list[i].sock) {
			fprintf(stderr, "failed to malloc sock queue\n");
			/* Free all previous allocated work queues */
			if (i > 0)
				free_work_queue_list(work_queue_list, i - 1);
			return NULL;
		}
	}

	return work_queue_list;
}

int sock_read(int sock)
{
	int ret;
	char *buffer;

	buffer = malloc(MAX_BUFFER);
	if (!buffer) {
		fprintf(stderr, "malloc buffer\n");
		return -1;
	}

	ret = recv(sock, buffer, MAX_BUFFER, 0);
	if (ret < 0) {
		err_msg("recv");
		ret = -1;
		goto free_buf;
	} else if (ret == 0) {
		ret = -1;
		goto free_buf;
	}

	/* TODO: We should ensure that we read all the data */

	ret = send(sock, buffer, ret, 0);
	if (ret < 0) {
		err_msg("send");
		ret = -1;
		goto free_buf;
	}

	ret = 0;
free_buf:
	free(buffer);
	return ret;
}

int clean_up_sock(int epoll_fd, int sock)
{
	int ret;

	ret = epoll_ctl(epoll_fd, EPOLL_CTL_DEL, sock, NULL);
	if (ret < 0) {
		err_msg("epoll-ctl delete");
		close(sock);
		return -1;
	}
	close(sock);
}

void *thread_handler(void *arg)
{
	struct thread_data *data = (struct thread_data *) arg;
	int epoll_fd = data->epoll_fd;
	struct work_queue *wq = data->wq;
	int sock, ret;

	while(1) {
		sock = pop_work(wq);
		if (sock_read(sock) < 0)
			clean_up_sock(epoll_fd, sock);
	}

	return NULL;
}

struct work_queue *setup_worker_pool(int epoll_fd)
{
	struct work_queue *work_queue_list;
	pthread_t *threads;
	int i;

	work_queue_list = setup_work_queue_list(num_of_cpus);
	if (!work_queue_list) {
		fprintf(stderr, "failed to setup work queue list\n");
		return NULL;
	}

	threads = malloc(num_of_cpus * sizeof(pthread_t));
	if (!threads) {
		fprintf(stderr, "failed to malloc threads\n");
		free_work_queue_list(work_queue_list, num_of_cpus);
		return NULL;
	}

	for (i = 0; i < num_of_cpus; i++) {
		struct thread_data *data;

		data = malloc(sizeof(struct thread_data));
		if (!data) {
			int j;

			for (j = 0; j < i; j++)
				pthread_kill(threads[j], SIGTERM);

			free(threads);
			free_work_queue_list(work_queue_list, num_of_cpus);
			return NULL;
		}

		data->epoll_fd = epoll_fd;
		data->wq = &work_queue_list[i];

		pthread_create(&threads[i], NULL, thread_handler, data);
	}

	return work_queue_list;
}

int handle_listen_sock(int epoll_fd, int listen_sock)
{
	int sock, ret;
	struct epoll_event event;

	sock = accept(listen_sock, NULL, NULL);
	if (sock < 0) {
		err_msg("accept");
		return -1;
	}

	event.events = EPOLLIN | EPOLLET;
	event.data.fd = sock;
	ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock, &event);
	if (ret < 0) {
		err_msg("epoll-ctl add sock read");
		return -1;
	}

	return 0;
}

int handle_sock_read(int sock, struct work_queue *work_queue_list)
{
	static int assigned_thread = 0;

	enqueue_work(&work_queue_list[assigned_thread], sock);
	assigned_thread = (assigned_thread + 1) % num_of_cpus;
}

int main()
{
	int ret, listen_sock, epoll_fd, sockopt;
	struct epoll_event event = {};
	struct epoll_event ready_event[MAX_EVENTS];
	struct sockaddr_in saddr = {
		.sin_family = AF_INET,
		.sin_addr = inet_addr(HOST),
		.sin_port = htons(PORT),
	};
	struct work_queue *work_queue_list;

	num_of_cpus = sysconf(_SC_NPROCESSORS_ONLN) / 2;
	/* ceil(MAX_SOCKETS / num_of_cpus) */
	sock_queue_size = (MAX_SOCKETS + num_of_cpus - 1) / num_of_cpus;

	epoll_fd = epoll_create(MAX_SOCKETS);
	if (epoll_fd < 0)
		err_exit("epoll-create");

	work_queue_list = setup_worker_pool(epoll_fd);
	if (!work_queue_list) {
		fprintf(stderr, "failed to setup worker pool\n");
		exit(1);
	}

	listen_sock = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_sock < 0)
		err_exit("socket");

	sockopt = 1;
	ret = setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &sockopt,
			 sizeof(sockopt));
	if (ret < 0)
		err_exit("setsockopt");

	ret = bind(listen_sock, (struct sockaddr *)&saddr, sizeof(saddr));
	if (ret < 0)
		err_exit("bind");

	ret = listen(listen_sock, BACKLOG);
	if (ret < 0)
		err_exit("listen");

	printf("Server socket is listening on %s:%d\n", HOST, PORT);

	event.events = EPOLLIN;
	event.data.fd = listen_sock;
	ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_sock, &event);
	if (ret < 0)
		err_exit("epoll-ctl");

	while (1) {
		int i;

		ret = epoll_wait(epoll_fd, ready_event, MAX_EVENTS, -1);
		if (ret < 0) {
			err_msg("epoll-wait");
			continue;
		}

		for (i = 0; i < ret; i++) {
			if (ready_event[i].events & EPOLLIN) {
				if (ready_event[i].data.fd == listen_sock)
					handle_listen_sock(epoll_fd, listen_sock);
				else
					handle_sock_read(ready_event[i].data.fd,
							 work_queue_list);
			} else {
				fprintf(stderr, "unexpected poll event: 0x%x\n",
					ready_event[i].events);
			}
		}
	}

	return 0;
}
