#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <error.h>
#include <asm/socket.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>

#include <netlink/socket.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/netlink.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <linux/mptcp_pm.h>
#include <linux/mptcp.h>

#define HOST "0.0.0.0"
#define PORT 8888

#define BUFFER_SIZE 1024

int cfg_ifindex;
struct in_addr cfg_ip;

void print_usage(const char *prog)
{
	error(1, 0, "Usage: %s -i <additional_ifname> -a <additional_ip>",
	      prog);
}

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
 * - ip mptcp endpoint add <additional_ip> dev <additional_ifname> signal
 */
void add_addr(struct nl_sock *sock, int family_id)
{
	struct nl_msg *msg;
	struct nlattr *attr;
	int ret;

	msg = nlmsg_alloc();
	if (!msg)
		error(1, 0, "nlmsg_alloc()");

	genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id, 0, 0,
		    MPTCP_PM_CMD_ADD_ADDR, 0);
	
	attr = nla_nest_start(msg, MPTCP_PM_ENDPOINT_ADDR);
	NLA_PUT_U16(msg, MPTCP_PM_ADDR_ATTR_FAMILY, AF_INET);
	NLA_PUT_U32(msg, MPTCP_PM_ADDR_ATTR_ADDR4, cfg_ip.s_addr);
	NLA_PUT_S32(msg, MPTCP_PM_ADDR_ATTR_IF_IDX, cfg_ifindex);
	NLA_PUT_U32(msg, MPTCP_PM_ADDR_ATTR_FLAGS, MPTCP_PM_ADDR_FLAG_SIGNAL);
	nla_nest_end(msg, attr);

	ret = nl_send_auto(sock, msg);
	if (ret < 0)
		error(1, 0, "nl_send_auto(), err: %d", ret);

	/* TODO: receive the message to check the successful status */
	
	nlmsg_free(msg);
	return;

nla_put_failure:
	nlmsg_free(msg);
	error(1, 0, "nla_put failed");
}

void parse_opts(int argc, char **argv)
{
	int opt, ret;
	char *ifname = NULL;
	char *ip = NULL;

	while ((opt = getopt(argc, argv, "hi:a:")) != -1) {
		switch (opt) {
		case 'i':
			ifname = optarg;
			break;
		case 'a':
			ip = optarg;
			break;
		case 'h':
		default:
			print_usage(argv[0]);
		}
	}

	if (!ifname || !ip)
		print_usage(argv[0]);

	cfg_ifindex = if_nametoindex(ifname);
	if (!cfg_ifindex)
		error(1, errno, "if_nametoindex()");

	ret = inet_pton(AF_INET, ip, &cfg_ip);
	if (ret <= 0)
		error(1, 0, "inet_pton()");
}

int main(int argc, char **argv)
{
	int sock, ret, connected_sock, family_id;
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_addr = inet_addr(HOST),
		.sin_port = htons(PORT),
	};
	int addr_len;
	char addr_str[INET_ADDRSTRLEN];
	int protocol;
	char buffer[BUFFER_SIZE];
	struct nl_sock *netlink_sk;

	parse_opts(argc, argv);

	netlink_sk = init_netlink();
	family_id = genl_ctrl_resolve(netlink_sk, MPTCP_PM_NAME);
	if (family_id < 0)
		error(1, 0, "genl_ctrl_resolve(), err: %d", family_id);

	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
	if (sock < 0)
		error(1, errno, "socket()");

	ret = bind(sock, (const struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0)
		error(1, errno, "bind()");

	ret = listen(sock, 10);
	if (ret < 0)
		error(1, errno, "listen()");

	memset(&addr, 0, sizeof(addr));
	addr_len = sizeof(addr);
	connected_sock = accept(sock, (struct sockaddr *)&addr, &addr_len);
	if (connected_sock < 0)
		error(1, errno, "accept()");

	addr_len = sizeof(protocol);
	ret = getsockopt(connected_sock, SOL_SOCKET, SO_PROTOCOL, &protocol,
			 &addr_len);
	if (ret < 0)
		error(1, errno, "getsockopt()");

	add_addr(netlink_sk, family_id);

	if (!inet_ntop(AF_INET, &addr.sin_addr.s_addr, addr_str,
		       sizeof(addr_str)))
		error(1, errno, "inet_ntop()");
	printf("Receive connection from: %s:%d, prot: %d\n",
	       addr_str, addr.sin_port, protocol);

	ret = recv(connected_sock, buffer, sizeof(buffer), 0);
	if (ret < 0)
		error(1, errno, "recv()");

	puts("Press ENTER to continue");
	scanf("%*c");

	return 0;
}
