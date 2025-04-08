all:
	gcc -o xsk xsk.c -lbpf

generate:
	clang -O2 -g -target bpf -c xsk_bpf.c -o xsk_bpf.o
	bpftool gen skeleton xsk_bpf.o > xsk_bpf.skeleton.h

static:
	gcc -static -o xsk xsk.c -lbpf -lelf -lzstd -lz
