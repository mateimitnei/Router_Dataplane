/* Matei Mițnei 323CD */

#include "extra.h"

// Lungimea unui pachet ICMP type 3 si 11
#define ICMP_LEN sizeof(struct ether_hdr) + 2 * sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + 8

struct route_table_entry *rtable;
struct route_table_entry *best_route;
int rtable_len;

struct arp_table_entry *arp_table;
int arp_table_len;

queue ip_packet_queue;

// LPM prin cautare binara
struct route_table_entry *get_best_route(uint32_t ip_dest) {

	int mid, left = 0, right = rtable_len - 1;
    struct route_table_entry *found = NULL;

    while (left <= right) {
        mid = (left + right) / 2;
        struct route_table_entry *entry = &rtable[mid];

        // Daca este ruta potrivita
        if ((ip_dest & entry->mask) == entry->prefix) {
            found = entry;
            // Continuare cautare pentru un posibil prefix mai lung
            right = mid - 1;
        } else if (ntohl(ip_dest & entry->mask) < ntohl(entry->prefix)) {
            left = mid + 1;
        } else {
            right = mid - 1;
        }
    }

    return found;
}

// Cautare in tabela ARP
uint8_t *get_next_mac(uint32_t ip_dest) {

    for (int i = 0; i < arp_table_len; i++) {
        if (arp_table[i].ip == ip_dest) {
            return arp_table[i].mac;
        }
    }
    return NULL;
}

// Verificari pentru pachetul IP

/* Intoarce:
   1 = pachet procesat cu succes
   0 = pachet ICMP
  -1 = pachet invalid, checksum gresit
*/
int process_ip_packet(struct ip_hdr *iphdr, uint32_t router_ip, char *buf, size_t *len) {
    
    // Verificare integritate cu checksum
    uint16_t sum = iphdr->checksum;
    iphdr->checksum = 0;

    if (ntohs(sum) != checksum((uint16_t *)iphdr, sizeof(struct ip_hdr))) {
        return -1;
    }

    // Verificare destinatie IP
    if (iphdr->dest_addr == router_ip) {

        struct icmp_hdr *icmphdr = (struct icmp_hdr *)(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
        if (icmphdr->mtype == 8) {
            // Pachet ICMP care pastreaza continutul original, de tip "Echo reply" (type 0)
            iphdr->ttl = 64;
            iphdr->dest_addr = iphdr->source_addr;
            iphdr->source_addr = router_ip;

            icmphdr->mtype = 0;
            icmphdr->check = 0;
            icmphdr->check = htons(checksum((uint16_t *)icmphdr, *len - sizeof(struct ether_hdr) - sizeof(struct ip_hdr)));
        }
        return 0;
    }

    // Verificare time to leave
    if (iphdr->ttl <= 1) {
        // Pachet ICMP de tip "Time exceeded" (type 11)
        create_icmp(buf, 11, 0, router_ip);
        *len = ICMP_LEN;
        
        return 0;
    }

    // Actualizare checksum
    iphdr->ttl--;
    iphdr->checksum = 0;
    iphdr->checksum = htons(checksum((uint16_t *)iphdr, sizeof(struct ip_hdr)));

    // Cautare si verificare next hop
    best_route = get_best_route(iphdr->dest_addr);

    if (best_route == NULL) {
        // Pachet ICMP de tip "Destination unreachable" (type 3)
        create_icmp(buf, 3, 0, router_ip);
        *len = ICMP_LEN;

        return 0;
    }

    return 1;
}

// Introduce perechea IP-MAC in tabela ARP si trimite pachetele IPv4 compatibile din coada
void process_arp_reply(struct arp_hdr *arphdr) {

    // Adaugrae in tabela ARP
    arp_table[arp_table_len].ip = arphdr->sprotoa;
    memcpy(arp_table[arp_table_len].mac, arphdr->shwa, 6);
    arp_table_len++;

    // Trimitere pachete din coada care au facut request pentru acest IP
    struct ip_queue_node *node;

    while ((node = dequeue_packet(ip_packet_queue, arphdr->sprotoa)) != NULL) {

        struct ether_hdr *etherhdr = (struct ether_hdr *)node->packet;
        memcpy(etherhdr->ethr_dhost, arphdr->shwa, 6); // MAC dest
        get_interface_mac(node->interface, etherhdr->ethr_shost); // MAC sursa

        send_to_link(node->len, node->packet, node->interface);
    }
}


int main(int argc, char *argv[]) {
	
    char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argv + 2, argc - 2);

    // Tabela de rutare
    rtable = malloc(sizeof(struct route_table_entry) * 100000);

    rtable_len = read_rtable(argv[1], rtable);
    qsort((void *)rtable, rtable_len, sizeof(struct route_table_entry), comparator);

    // Tabela ARP
    arp_table = malloc(sizeof(struct arp_table_entry) * 100);
    arp_table_len = 0;

    // Coada de pachete IP care asteapta ARP reply
    ip_packet_queue = create_queue();

	while (1) {

		size_t interface;
        size_t len;
		
		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_link");

        // Verificare pachet malformat

        if (len < sizeof(struct ether_hdr)) continue;

        uint8_t router_mac[6];
        get_interface_mac(interface, router_mac);

        uint32_t router_ip;
        inet_pton(AF_INET, get_interface_ip(interface), &router_ip);

        // Verificare destinatie MAC
        
        struct ether_hdr *etherhdr = (struct ether_hdr *)buf;

        if (memcmp(etherhdr->ethr_dhost, router_mac, 6) != 0 &&
            memcmp(etherhdr->ethr_dhost, "\xFF\xFF\xFF\xFF\xFF\xFF", 6) != 0) {
            continue;
        }

        // Identificare tip pachet

        if (ntohs(etherhdr->ethr_type) == 0x0800) { // IPv4
            
            struct ip_hdr *iphdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));

            // Procesare pachet

            int res = process_ip_packet(iphdr, router_ip, buf, &len);
            if (res == -1){
                continue;
            }
            else if (res == 0) {
                // Pentru pachete ICMP
                best_route = get_best_route(iphdr->dest_addr);
            }

            // Actualizare header ethernet

            uint8_t *next_mac = get_next_mac(best_route->next_hop);
            if (next_mac == NULL) {
                // Adaugare in coada de asteptare si trimitere ARP request

                enqueue_packet(ip_packet_queue, buf, len, best_route->next_hop, best_route->interface);
                
                uint8_t sender_mac[6];
                get_interface_mac(best_route->interface, sender_mac);
                
                uint32_t sender_ip;
                inet_pton(AF_INET, get_interface_ip(best_route->interface), &sender_ip);

                send_arp_packet(sender_ip, sender_mac, best_route->next_hop, NULL, best_route->interface, 1);
                continue;
            }
            
            memcpy(etherhdr->ethr_dhost, next_mac, 6);
            memcpy(etherhdr->ethr_shost, router_mac, 6);

            // Trimitere pachet ethernet

            size_t ret = send_to_link(len, buf, best_route->interface);
            DIE(ret < 0, "send_to_link");

        } else if (ntohs(etherhdr->ethr_type) == 0x0806) { // ARP

            struct arp_hdr *arphdr = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));
            
            if (ntohs(arphdr->opcode) == 2) { // ARP reply
                process_arp_reply(arphdr);
            
            } else if (ntohs(arphdr->opcode) == 1) { // ARP request
                send_arp_packet(router_ip, router_mac, arphdr->sprotoa, arphdr->shwa, interface, 2);
            }
        }
	}

    free(rtable);
    free(arp_table);

    return 0;
}
