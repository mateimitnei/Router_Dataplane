#include "extra.h"


// Functie parametru pentru qsort
int comparator(const void *a, const void *b) {

    struct route_table_entry *a1 = (struct route_table_entry *)a;
    struct route_table_entry *b1 = (struct route_table_entry *)b;

    if (a1->mask == b1->mask) {
        return ntohl(b1->prefix) - ntohl(a1->prefix);
    } else {
        return ntohl(b1->mask) - ntohl(a1->mask);
    }
}


// Creaza un pachet cu ICMP care schimba destinatia in adresa ip a sursei
void create_icmp(char *packet, uint8_t type, uint8_t code, uint32_t router_ip) {

    char copy[MAX_PACKET_LEN];
    memcpy(copy, packet, MAX_PACKET_LEN);
    memset(packet, 0, MAX_PACKET_LEN);

    struct ether_hdr *eth_hdr = (struct ether_hdr *)packet;
    struct ip_hdr *iphdr = (struct ip_hdr *)(packet + sizeof(struct ether_hdr));
    struct icmp_hdr *icmphdr = (struct icmp_hdr *)(packet + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

    struct ip_hdr *old_iphdr = (struct ip_hdr *)(copy + sizeof(struct ether_hdr));

    // Header ethernet
    // MAC dest si source sunt completate ulterior, in router.c
    eth_hdr->ethr_type = htons(0x0800); // Pentru IPv4
    
    // Header IP
    iphdr->ihl = 5;
    iphdr->ver = 4;
    iphdr->tos = 0;
    iphdr->tot_len = htons(2 * sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + 8);
    iphdr->id = 4;
    iphdr->frag = 0;
    iphdr->ttl = 64;
    iphdr->proto = 1; // pentru ICMP
    iphdr->source_addr = router_ip;
    iphdr->dest_addr = old_iphdr->source_addr;

    iphdr->checksum = 0;
    iphdr->checksum = htons(checksum((uint16_t *)iphdr, sizeof(struct ip_hdr)));

    // Adaugare header IP original si 64 biti (8 octeti) din payload
    memcpy((uint8_t *)icmphdr + sizeof(struct icmp_hdr), old_iphdr, sizeof(struct ip_hdr) + 8);

    // Creare ICMP
    icmphdr->mtype = type;
    icmphdr->mcode = code;
    icmphdr->check = 0;
    icmphdr->check = htons(checksum((uint16_t *)icmphdr, sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8));
}


// Creaza pachet ARP (reply sau request in functie de parametrul opcode)
void send_arp_packet(uint32_t sender_ip, uint8_t *sender_mac,
    uint32_t target_ip, uint8_t *target_mac, size_t interface, uint16_t opcode) {

    char buf[MAX_PACKET_LEN];
    memset(buf, 0, MAX_PACKET_LEN);

    struct ether_hdr *etherhdr = (struct ether_hdr *)buf;
    struct arp_hdr *arphdr = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));

    if (opcode == 1) { // ARP Request
        memset(etherhdr->ethr_dhost, 0xFF, 6);
        memset(arphdr->thwa, 0, 6);

    } else if (opcode == 2) { // ARP Reply
        memcpy(etherhdr->ethr_dhost, target_mac, 6);
        memcpy(arphdr->thwa, target_mac, 6);
    }

    memcpy(etherhdr->ethr_shost, sender_mac, 6); // MAC-ul sursă
    etherhdr->ethr_type = htons(0x0806); // tip ARP

    // Antet ARP
    arphdr->hw_type = htons(1);
    arphdr->proto_type = htons(0x0800);
    arphdr->hw_len = 6;
    arphdr->proto_len = 4;
    arphdr->opcode = htons(opcode);
    arphdr->sprotoa = sender_ip;
    arphdr->tprotoa = target_ip;
    memcpy(arphdr->shwa, sender_mac, 6);

    send_to_link(sizeof(struct ether_hdr) + sizeof(struct arp_hdr), buf, interface);
}

// Adauga un pachet IP in coada
void enqueue_packet(queue ip_packet_queue, char *packet, size_t len, uint32_t next_hop_ip, size_t interface) {

    struct ip_queue_node *node = malloc(sizeof(struct ip_queue_node));

    memcpy(node->packet, packet, len);
    node->len = len;
    node->next_hop = next_hop_ip;
    node->interface = interface;

    queue_enq(ip_packet_queue, node);
}

// Returneaza si elimina primul pachet IP din coada cu next_hop == next_hop_ip
struct ip_queue_node *dequeue_packet(queue ip_packet_queue, uint32_t next_hop_ip) {

    struct ip_queue_node *first_found = NULL;
    queue inverted_queue = create_queue();

    int dequeues_num = 0;

    while (!queue_empty(ip_packet_queue)) {
        
        struct ip_queue_node *node = queue_deq(ip_packet_queue);
        dequeues_num++;

        if (node->next_hop == next_hop_ip && first_found == NULL) {
            first_found = node;
            if (dequeues_num == 1) {
                break;
            }
        } else {
            queue_enq(inverted_queue, node);
        }
    }

    if (dequeues_num > 1) {
        // Recostruire coada originala (fara nodul gasit)
        while (!queue_empty(inverted_queue)) {
            queue_enq(ip_packet_queue, queue_deq(inverted_queue));
        }
    }

    return first_found;
}
