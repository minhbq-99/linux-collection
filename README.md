# Toy echo server

My toy project to learn how to use epoll, io_uring to write a performant server.

Currently, the benchmark is on the localhost interface
- iperf:
```
iperf -t 30 -c 127.0.0.1 -p 8888
[  1] 0.0000-30.0120 sec   128 GBytes  36.7 Gbits/sec (~4.59 GB/s)
```

- single thread epoll:
```
./client --client 32 --packet.size 32768 --duration 30s
Sent: 71642.48 req/s. Received: 71641.41 req/s
DataSent: 2.19 GB/s. Received: 2.19 GB/s
```

- multithread epoll:
```
./client --client 32 --packet.size 32768 --duration 30s
Sent: 151863.93 req/s. Received: 151862.86 req/s
DataSent: 4.63 GB/s. Received: 4.63 GB/s
```

