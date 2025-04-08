# XDP socket on virtio-net
- A simple code to explore how virtio-net supports XDP socket

### Project structure
- xsk_bpf.c: a eBPF XDP program that redirects UDP socket to XDP socket
- xsk_bpf.skeleton.h: the generated code from the above eBPF program, which
helps to manage and load the program easily
- xsk.c: the main code which sets up XDP socket, binds it and the eBPF XDP
program to virtio-net interface
