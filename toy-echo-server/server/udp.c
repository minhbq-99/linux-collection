/* A UDP server which uses SO_REUSEPORT to reduce contention in receive queue */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <poll.h>
#include <sched.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define err_msg(msg) do { \
	int val = 1; \
	perror(msg); \
	pthread_exit(&val); \
} while(0)

#define HOST "0.0.0.0"
#define PORT 8888

#define BUFFER_SIZE 2048

static int reuseport = 1;
static int incoming_cpu;

void *thread_handler(void *arg)
{
	int sock, val, ret;
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_addr = inet_addr(HOST),
		.sin_port = htons(PORT),
	};
	char buffer[BUFFER_SIZE];
	int num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	cpu_set_t set = {};
	int i = (int)(long)arg;
	int count = 0;

	CPU_SET(i % num_cpus, &set);
	ret = sched_setaffinity(0, sizeof(set), &set);
	if (ret < 0)
		err_msg("sched_setaffinity");

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
		err_msg("socket");

	if (reuseport) {
		val = 1;
		ret = setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &val,
				 sizeof(val));
		if (ret < 0)
			err_msg("setsockopt SO_REUSEPORT");
	}

	if (incoming_cpu) {
		val = i % num_cpus;
		ret = setsockopt(sock, SOL_SOCKET, SO_INCOMING_CPU, &val,
				 sizeof(val));
		if (ret < 0)
			err_msg("setsockopt SO_INCOMING_CPU");
	}

	ret = bind(sock, &addr, sizeof(addr));
	if (ret < 0)
		err_msg("bind");

	while(1) {
		int received_bytes;
		struct sockaddr_in client_addr = {};
		struct iovec iov = {
			.iov_base = buffer,
			.iov_len = sizeof(buffer),
		};
		struct msghdr msg = {
			.msg_name = &client_addr,
			.msg_namelen = sizeof(client_addr),
			.msg_iov = &iov,
			.msg_iovlen = 1,
		};

		received_bytes = recvmsg(sock, &msg, 0);
		if (received_bytes < 0)
			err_msg("recv");

		iov.iov_len = received_bytes;
		ret = sendmsg(sock, &msg, 0);
		if (ret < 0)
			err_msg("send");

		if (ret != received_bytes)
			fprintf(stderr, "Echo response is truncated, "
				"expected: %d sent: %d\n",
				received_bytes, ret);
		count++;
		if (count % 500000 == 0)
			printf("Thread: %d, Count: %d\n", i, count);
	}
}

void print_usage(const char *prog)
{
	fprintf(stderr, "Usage: %s [-t num_threads] [-c]\n\nwhere:\n"
		"\t-t num_threads: number of handling threads in the server\n"
		"\t-c:\t\tuse SO_INCOMING_CPU when setting up socket\n",
		prog);
}

int main(int argc, char **argv)
{
	int opt, i, ret, num_threads = 0;
	pthread_t *threads;

	while ((opt = getopt(argc, argv, "ht:c")) != -1) {
		switch (opt) {
		case 't':
			num_threads = atoi(optarg);
			if (!num_threads) {
				fprintf(stderr, "Invalid number of threads\n");
				return 1;
			}
			break;
		case 'c':
			incoming_cpu = 1;
			break;
		case 'h':
		default:
			print_usage(argv[0]);
			return 1;
		}
	}

	if (!num_threads)
		num_threads = sysconf(_SC_NPROCESSORS_ONLN);

	threads = malloc(num_threads * sizeof(*threads));
	if (!threads) {
		fprintf(stderr, "Failed to malloc threads\n");
		return 1;
	}

	printf("Num threads: %d\n", num_threads);
	if (num_threads == 1)
		reuseport = 0;

	for (i = 0; i < num_threads; i++) {
		ret = pthread_create(&threads[i], NULL, thread_handler,
				     (void *)(long)i);
		if (ret) {
			fprintf(stderr, "Failed to create thread, err: %d\n",
				ret);
			return 1;
		}
	}

	for (i = 0; i < num_threads; i++)
		pthread_join(threads[i], NULL);

	return 0;
}
