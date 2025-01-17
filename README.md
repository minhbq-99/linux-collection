# Toy echo server

My toy project to learn how to use epoll, io_uring to write a performant server.

Currently, the benchmark is on the localhost interface
- iperf:
iperf -t 30 -c 127.0.0.1 -p 8888
[  1] 0.0000-30.0012 sec   174 GBytes  50.0 Gbits/sec (6.25 GB/s)

- single thread epoll:
./client --client 32 --packet.size 32768 --duration 30s
Sent: 99042.79 req/s. Received: 99041.72 req/s
DataSent: 3.02 GB/s. Received: 3.02 GB/s

- multithread epoll:
./client --client 32 --packet.size 32768 --duration 30s
Sent: 204423.44 req/s. Received: 204422.38 req/s
DataSent: 6.24 GB/s. Received: 6.24 GB/s

