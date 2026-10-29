# Router Dataplane 🌐
### Author: Matei Mițnei


## Description

This project implements the dataplane of an IPv4 router in C. The router receives Ethernet frames, inspects their headers and decides what to do with them: forward an IP packet toward its destination, reply to an ARP query, or generate an ICMP reply/error when something goes wrong.

The core responsibilities are:

- **Packet forwarding**: looks up the destination IP in a static routing table using Longest Prefix Match (binary search) and forwards the packet to the correct next hop.
- **ARP resolution**: dynamically learns MAC addresses by sending ARP requests and caching replies. Packets waiting for an unresolved MAC are queued and sent once the reply arrives.
- **ICMP handling**: responds to echo requests (ping) aimed at the router or generates error messages for expired TTL (type 11) or unreachable destinations (type 3).
- **Integrity checks**: validates checksums, drops malformed packets and ignores frames not addressed to the router.


## Checker & Test Topology

This project has an automated checker (not implemented by me) built on top of [Mininet](http://mininet.org/), which emulates a small network locally with a topology that looks like this:

```
   ┌───────┐                                   ┌───────┐
   │ host0 ├──┐                            ┌───┤ host2 │
   └───────┘  │   ┌─────────┐ ┌─────────┐  │   └───────┘
              ├───┤ router0 ├─┤ router1 ├──┤
   ┌───────┐  │   └─────────┘ └─────────┘  │   ┌───────┐
   │ host1 ├──┘                            └───┤ host3 │
   └───────┘                                   └───────┘
```

- **2 routers** (`router0`, `router1`): each runs the compiled `router` binary with its own routing table (`rtable0.txt`, `rtable1.txt`). They are connected to each other through a direct link.
- **4 hosts** (`host0`–`host3`): two per router. Each host has a single interface pointed at its local router as the default gateway.

Every node has predefined IP and MAC addresses (configured in `checker/info.py`). IPv6, kernel IP forwarding and NIC checksum offload are all disabled so the router implementation has full control over the packet pipeline.

The checker (`checker/checker.sh`) builds the project, boots the Mininet topology, runs a suite of tests (ICMP, forwarding, ARP request/reply, TTL, etc.) and reports a score out of 100.


## Implementation Overview

[**`router.c`**](router.c) contains the main logic. On startup, the routing table is loaded from a file and an empty ARP table is created (it gets populated dynamically at runtime). The main loop receives packets and runs a few sanity checks before doing anything with them: the packet must be at least as large as an Ethernet header and its destination MAC must match the router's own address or the broadcast address.

**IPv4 packets** are handed off to `process_ip_packet()`:
```c
/* Returns:
1 = packet processed successfully
0 = ICMP packet
-1 = invalid packet, bad checksum
*/
int process_ip_packet(struct ip_hdr *iphdr, uint32_t router_ip, char *buf, size_t *len)
```
This function first validates the checksum. If the packet is an ICMP echo request aimed at the router itself, the source and destination addresses are simply swapped to form an echo reply. Next, the TTL is checked: if it has expired, the original packet in `buf` is replaced with an ICMP error (type=11, code=0) via `create_icmp()`. Otherwise, the TTL is decremented and the checksum recalculated.

The next hop is then determined by `get_best_route()`, which performs a binary search over the routing table (pre-sorted in descending order by prefix length). If no matching route is found, `buf` is again replaced with an ICMP error (type=3, code=0), just like the TTL-expired case.

Back in main, the router looks up the next hop's MAC address in the ARP table using `get_next_mac()`. If the MAC is not yet known, the packet is placed in `ip_packet_queue` to be sent later and an ARP request is broadcast via `send_arp_packet()`. If the MAC is already available, the Ethernet header is updated with the correct addresses and the packet is forwarded out through `best_route->interface`.

**ARP reply** packets are handled by `process_arp_reply()`:
```c
// Inserts the IP-MAC pair into the ARP table
// and sends any queued IPv4 packets that were waiting for it
void process_arp_reply(struct arp_hdr *arphdr)
```
The sender's IP and MAC (from `arphdr->sprotoa` and `arphdr->swa`) are added to the ARP table. Then the pending packet queue is drained with `dequeue_packet` and any packets whose next hop matches the newly learned address are sent out.

**ARP request** packets are answered directly by sending back an ARP reply through `send_arp_packet`.

[**`lib/extra.c`**](lib/extra.c) provides helper functions used throughout `router.c`:
   - `enqueue_packet` / `dequeue_packet`: queue management for packets awaiting ARP resolution.
   - `create_icmp`: builds an ICMP error packet by appending the original IPv4 header plus 64 bits of the original payload after the ICMP header.
   - `send_arp_packet`: constructs and sends an ARP packet; the `uint16_t opcode` parameter controls whether it's a request (1) or a reply (2).
   - `comparator`: comparison function for `qsort`, used to sort routing table entries in descending order by prefix length.
