#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#define err_exit(msg) do {perror(msg); exit(1);} while(0)
#define err_msg(msg) fprintf(stderr, msg ": %s\n", strerror(errno))

#define HOST "0.0.0.0"
#define PORT 8888
#define BACKLOG 512

#define MAX_SOCKETS 8192
#define MAX_EVENTS 512
#define MAX_BUFFER 32768

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

int handle_listen_sock(int epoll_fd, int listen_sock)
{
	int sock, ret;
	struct epoll_event event;

	sock = accept(listen_sock, NULL, NULL);
	if (sock < 0) {
		err_msg("accept");
		return -1;
	}

	event.events = EPOLLIN;
	event.data.fd = sock;
	ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock, &event);
	if (ret < 0) {
		err_msg("epoll-ctl add sock read");
		return -1;
	}

	return 0;
}

int handle_sock_read(int sock)
{
	sock_read(sock);
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

	epoll_fd = epoll_create(MAX_SOCKETS);
	if (epoll_fd < 0)
		err_exit("epoll-create");

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
					handle_sock_read(ready_event[i].data.fd);
			} else {
				fprintf(stderr, "unexpected poll event: 0x%x\n",
					ready_event[i].events);
			}
		}
	}

	return 0;
}
