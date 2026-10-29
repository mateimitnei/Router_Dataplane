#include "protocols.h"
#include "lib.h"
#include "queue.h"

#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>

// Functie parametru pentru qsort
int comparator(const void *a, const void *b);

// Creaza un pachet cu ICMP care schimba destinatia in adresa ip a sursei
void create_icmp(char *packet, uint8_t type, uint8_t code, uint32_t router_ip);

// Creaza pachet ARP (reply sau request in functie de parametrul opcode)
void send_arp_packet(uint32_t sender_ip, uint8_t *sender_mac,
    uint32_t target_ip, uint8_t *target_mac, size_t interface, uint16_t opcode);

// Adauga un pachet IP in coada
void enqueue_packet(queue ip_packet_queue, char *packet, size_t len,
    uint32_t next_hop_ip, size_t interface);

// Returneaza si elimina primul pachet IP din coada cu next_hop == next_hop_ip
struct ip_queue_node *dequeue_packet(queue ip_packet_queue, uint32_t next_hop_ip);
