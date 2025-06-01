#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <error.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

#include <netlink/socket.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/netlink.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <linux/mptcp_pm.h>

#define HOST "192.168.31.3"
#define PORT 8888

#define BUFFER_SIZE 1024

#define ADD_ADDR_LIMIT 1

struct nl_sock *init_netlink()
{
	int ret, family_id;
	struct nl_sock *sock;

	sock = nl_socket_alloc();
	if (!sock)
		error(1, 0, "nl_socket_alloc()");

	ret = genl_connect(sock);
	if (ret < 0)
		error(1, 0, "genl_connect(), err: %d", ret);

	return sock;
}

/*
 * This is the same as:
 * - ip mptcp limits set add_addr_accepted 1
 */
void set_add_addr_limit(struct nl_sock *sock, int family_id)
{
	int ret;
	struct nl_msg *msg;
	struct sockaddr_nl addr;
	unsigned char **buf;
	struct nlattr *tb[MPTCP_PM_ATTR_MAX];

	buf = malloc(sysconf(_SC_PAGESIZE));
	if (!buf)
		error(1, 0, "malloc()");

	msg = nlmsg_alloc();
	if (!msg)
		error(1, 0, "nlmsg_alloc()");

	genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id, 0, 0,
		    MPTCP_PM_CMD_GET_LIMITS, 0);
	
	ret = nl_send_auto(sock, msg);
	if (ret < 0)
		error(1, 0, "nl_send_auto(), err: %d", ret);

	ret = nl_recv(sock, &addr, buf, NULL);
	if (ret < 0)
		error(1, 0, "nl_recv(), err: %d", ret);

	ret = genlmsg_parse((struct nlmsghdr *)(*buf), 0, tb, MPTCP_PM_ATTR_MAX,
			    NULL);
	if (ret < 0)
		error(1, 0, "genlmsg_parse(), err: %d", ret);
 
	if (!tb[MPTCP_PM_ATTR_RCV_ADD_ADDRS])
		error(1, 0, "missing MPTCP_PM_ATTR_RCV_ADD_ADDRS attr");

	ret = *(int *)(nla_data(tb[MPTCP_PM_ATTR_RCV_ADD_ADDRS]));
	printf("Current add addr limit: %d\n", ret);
	nlmsg_free(msg);
	free(buf);

	if (ret != ADD_ADDR_LIMIT) {
		msg = nlmsg_alloc();
		if (!msg)
			error(1, 0, "nlmsg_alloc()");

		genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id, 0, 0,
			    MPTCP_PM_CMD_SET_LIMITS, 0);
		ret = nla_put_u32(msg, MPTCP_PM_ATTR_RCV_ADD_ADDRS,
				  ADD_ADDR_LIMIT);
		if (ret < 0)
			error(1, 0, "nla_put_u32(), err: %d", ret);

		ret = nl_send_auto(sock, msg);
		if (ret < 0)
			error(1, 0, "nl_send_auto(), err: %d", ret);

		/* TODO: receive the message to check the successful status */

		nlmsg_free(msg);
	}
}

int main(int argc, char **argv)
{
	int sock, ret, family_id;
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(PORT),
	};
	char buffer[BUFFER_SIZE];
	struct nl_sock *netlink_sk;

	if (argc < 2)
		error(1, 0, "Usage: %s server_ip", argv[0]);


	netlink_sk = init_netlink();
	family_id = genl_ctrl_resolve(netlink_sk, MPTCP_PM_NAME);
	if (family_id < 0)
		error(1, 0, "genl_ctrl_resolve(), err: %d", family_id);

	set_add_addr_limit(netlink_sk, family_id);

	addr.sin_addr.s_addr = inet_addr(argv[1]);

	memset(buffer, 'A', sizeof(buffer));

	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
	if (sock < 0)
		error(1, errno, "socket()");

	ret = connect(sock, (const struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0)
		error(1, errno, "connect()");

	ret = send(sock, buffer, sizeof(buffer), 0);
	if (ret < 0)
		error(1, errno, "send()");

	puts("Press ENTER to continue");
	scanf("%*c");

	return 0;
}
