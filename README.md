Project report
#### Introduction
```text
Ebpf is a powerful tool for network packet processing. It can be used 
for monitoring network traffic, filtering as firewall, redirecting, 
and modify its content. Rust is a new language targeted for high performance 
and security. Not many ebpf programs were written in rust and the Aya framework
(Rust ebpf framework) is lack of documentation. The early program framework
BCC(BPF Compiler Collection) use C in kernel part and python in user part.
Python is very easy to learn and program but C is hard. Especially when
dealing with memory manually can easily make mistake and hard to debug.
Most importantly, BCC does not support CO-RE(compile once, run every where),
libbpf support CO-RE but C language in user part is still too hard for
many programmers. Aya framework provided CO-RE, and relatively easy programming
experience.
```
#### Design
```text
This project used 3 hooks provided by ebpf, XDP(Express Data Path),
TC(Traffic Classifier) ingress and TC egress. XDP provides fastest and lowest
level packet processing in NIC before entering the kernal. The 2 pros are
speed and first entrance monitoring. This means it is very suitable for
filtering incoming packet as a firewall and see packet that arrive but not
shown in tcpdump or wireshark. The 2 cons are limitation of egress traffic
and lack of support for packet modification. When the packet enter TC layer,
kernel provide some initial check, which means many unsafe block(rust require
this to ensure memory safety. An unsafe block means the programmer handles it)
are no longer need. And checksum functions start to be provided.

In the user part, the program reads or writes data from or to ebpf maps to
communicate with kernal part. There are some limitations in kernal part.
The kernel part only accept fixed sized data structure and cannot panic.
Both rust compiler and ebpf verifier helps to ensure these rules.

Although Rust can be used to write the entire user part. I believe Rust is
still harder then other programming languages such as python or java.
That is why I choose to implement a rest server only to expose data to other
programs. This keeps the difficulty to minimum.
```
#### XDP hook
```text
In the XDP hook, the program does two things, read data from raw frame and parse
it to construct a logic packet, display it(monitoring) or apply rules from user
(firewall).
```
#### TC hook
```text
In TC ingress hook, the program first check if the packet is for load balancing,
If yes, it will choose a backend and do a DNAT, modify checksum, and redirect to backend.

in TC egress hook, the program first check if the packet is a response packet.
if yes, it will do a SNAT, modify checksum, and reply to client.

Here checksum must be recalculated even if NIC offload was on.
```
#### Future work
```text
The backend still need to be hardcoded in this project, because somehow the routing rule
did not apply. In other word ARP information was missing. The hard coded MAC, 
IP and interface name are in docker compose file.
```
#### User guide
For generating a new ebpf project with initial template, use:
> cargo generate https://github.com/aya-rs/aya-template.git

To see output, the log level at least need to be info, set environment variable.
> RUST_LOG=info

build the program
> cargo build

This will generate a single binary in target/debug/myapp. Then run with privilege.
> RUST_LOG=info sudo -E target/debug/myapp --iface eth0

#### Example
```text
aya-log init ok
[INFO  myapp] successfully set the docker_br_idx=86
[INFO  myapp] HTTP server listening on 192.168.3.100:8000
```
> curl 192.168.3.100:8000/rules/drop/list\
> {}

> curl 192.168.3.100:8000/rules/drop/add --json '{"src": "192.168.3.101", "prefix_len": 24, "action": 0}'\
> [{"src":"192.168.3.101","prefix_len":24,"action":0}]

>  curl 192.168.3.100:8000/rules/drop/delete -X DELETE \\ \
> --json '{"src": "192.168.3.101", "prefix_len": 24, "action": 0}'
> 
> curl 192.168.3.100:8000/rules/drop/list
> 
> {}

```text
[INFO  myapp] rule added: 192.168.3.101/24 -> 0
[INFO  myapp] rule deleted: 192.168.3.101/24 -> 0
```
From 192.168.1.102
> curl 192.168.3.100
```text
[INFO  myapp] SRC IP: 192.168.3.102, DST IP: 192.168.3.100, SRC PORT: 41590, DST PORT: 80
[INFO  myapp] SRC action: 2
[INFO  myapp] enter ingress TC
[INFO  myapp] VIP IPv4 address: 192.168.3.100
[INFO  myapp] new connection successful
[INFO  myapp] DNAT 192.168.3.100:80 -> 172.18.0.3:80, backendMAC 42:83:d8:7:c:23, checksum 9581
[INFO  myapp] dest stored successful
[INFO  myapp] l3_csum_replace with 6403a8c0->30012ac
[INFO  myapp] l4_csum_replace with 6403a8c0->30012ac
[INFO  myapp] new SRC IP: 192.168.3.102, DST IP: 172.18.0.3, checksum: ad78
[INFO  myapp] enter engress TC
[INFO  myapp] SRC IP: 172.18.0.3, DST IP: 192.168.3.102, SRC PORT: 80, DST PORT: 41590
[INFO  myapp] SNAT 172.18.0.3->192.168.3.100 LB_MAC 0:15:5d:1:6a:b
[INFO  myapp] dest stored successful
[INFO  myapp] l3_csum_replace with 30012ac->6403a8c0
[INFO  myapp] l4_csum_replace with 30012ac->6403a8c0
[INFO  myapp] new SRC: 192.168.3.100:80 MAC: 0:15:5d:1:6a:b, DST: 192.168.3.102:41590 MAC: 0:15:5d:1:6a:d
```
Tcpdump on eth1(first 2 only)
```text
tcpdump: listening on eth1, link-type EN10MB (Ethernet), snapshot length 262144 bytes
15:37:54.379105 IP (tos 0x0, ttl 64, id 7456, offset 0, flags [DF], proto TCP (6), length 60)
    192.168.3.102.41590 > registry.libra.com.http: Flags [S], cksum 0x7be0 (correct), seq 3692311580, win 29200, options [mss 1460,sackOK,TS val 408684193 ecr 0,nop,wscale 7], length 0
        0x0000:  0015 5d01 6a0b 0015 5d01 6a0d 0800 4500
        0x0010:  003c 1d20 4000 4006 9581 c0a8 0366 c0a8
        0x0020:  0364 a276 0050 dc14 341c 0000 0000 a002
        0x0030:  7210 7be0 0000 0204 05b4 0402 080a 185c
        0x0040:  06a1 0000 0000 0103 0307
15:37:54.379276 IP (tos 0x0, ttl 63, id 0, offset 0, flags [DF], proto TCP (6), length 60)
    registry.libra.com.http > 192.168.3.102.41590: Flags [S.], cksum 0x8849 (incorrect -> 0x57c0), seq 1256871027, ack 3692311581, win 65160, options [mss 1460,sackOK,TS val 2950318174 ecr 408684193,nop,wscale 7], length 0
        0x0000:  0015 5d01 6a0d 0015 5d01 6a0b 0800 4500
        0x0010:  003c 0000 4000 3f06 b3a1 c0a8 0364 c0a8
        0x0020:  0366 0050 a276 4aea 5473 dc14 341d a012
        0x0030:  fe88 8849 0000 0204 05b4 0402 080a afda
        0x0040:  485e 185c 06a1 0103 0307
```
Tcpdump on br-backend(first 2 only)
```text
tcpdump: listening on br-backend, link-type EN10MB (Ethernet), snapshot length 262144 bytes
15:37:54.379129 IP (tos 0x0, ttl 64, id 7456, offset 0, flags [DF], proto TCP (6), length 60)
    192.168.3.102.41590 > 172.18.0.3.http: Flags [S], cksum 0x93d7 (correct), seq 3692311580, win 29200, options [mss 1460,sackOK,TS val 408684193 ecr 0,nop,wscale 7], length 0
        0x0000:  4283 d807 0c23 0015 5d01 6a0d 0800 4500
        0x0010:  003c 1d20 4000 4006 ad78 c0a8 0366 ac12
        0x0020:  0003 a276 0050 dc14 341c 0000 0000 a002
        0x0030:  7210 93d7 0000 0204 05b4 0402 080a 185c
        0x0040:  06a1 0000 0000 0103 0307
15:37:54.379235 IP (tos 0x0, ttl 64, id 0, offset 0, flags [DF], proto TCP (6), length 60)
    172.18.0.3.http > 192.168.3.102.41590: Flags [S.], cksum 0x7052 (incorrect -> 0x6fb7), seq 1256871027, ack 3692311581, win 65160, options [mss 1460,sackOK,TS val 2950318174 ecr 408684193,nop,wscale 7], length 0
        0x0000:  2e69 dce5 9cb0 4283 d807 0c23 0800 4500
        0x0010:  003c 0000 4000 4006 ca98 ac12 0003 c0a8
        0x0020:  0366 0050 a276 4aea 5473 dc14 341d a012
        0x0030:  fe88 7052 0000 0204 05b4 0402 080a afda
        0x0040:  485e 185c 06a1 0103 0307
```
#### conclusion
```text
Rust based ebpf program is easier and safer to implement. 
The obstacle is that the framework still lack of documentation. 
This new way of ebpf programming need more contribution from the community.
```