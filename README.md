# linux-collection
A collection of small programs that I use to learn more about Linux

- [toy-echo-server](./toy-echo-server/): 2 versions of echo server, one using
epoll and the other using io-uring
- [xsk](./xsk/): a program which uses eBPF XDP program and XDP socket to
redirect UDP packets from virtio-net network interface to userspace program