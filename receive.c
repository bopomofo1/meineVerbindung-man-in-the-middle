#include "header/receive.h"
#include "header/hacking.h"

void print_packets(struct packet_node *head) {
    struct packet_node *current = head;

    while (current != NULL) {
        printf("seq is #%u\n", current->seq);
        current = current->next_packet_node;
    }
}

void push_packet_node(struct packet_node *head, uint32_t seq, uint32_t ack) 
{
    struct packet_node *current = head;
    struct packet_node *new_node = (struct packet_node *) ec_malloc(sizeof(struct packet_node));
    new_node->seq = seq;
    new_node->ack = ack;

    while (current->next_packet_node != NULL) {
        current = current->next_packet_node;
    }
    current->next_packet_node = new_node;
}

int search_packets(struct packet_node *head, uint32_t seq, uint32_t ack) 
{
    struct packet_node *current = head;

    while (current != NULL) {
        if(current->seq == seq && current->ack == ack)
            return 1;
        current = current->next_packet_node;
    }
    return 0;
};

void decode_ip(struct libnet_ipv4_hdr *iphdr)
{
    printf("\t(( Layer 3 ::: IP Header ))\n");
    struct in_addr ip_address;
    ip_address = iphdr->ip_src;
    printf("\t( Source: %s\tDestination: ", inet_ntoa(ip_address));
    ip_address = iphdr->ip_dst;
    printf("%s )\n", inet_ntoa(ip_address));
}

void decode_tcp(struct libnet_tcp_hdr *tcphdr) 
{
    printf("\t\t{{ Layer 4 :::: TCP Header }}\n");
    printf("\t\t{Src. Port: %hu \t Dst. Port: %hu }\n", ntohs(tcphdr->th_sport), ntohs(tcphdr->th_dport));
    printf("\t\t{Seq #: %u \t Ack #: %u }\n", ntohl(tcphdr->th_seq), ntohl(tcphdr->th_ack));
    printf("\t\t{Header Size: %d \t Flags: ", ntohs(tcphdr->th_off) * 4);

    if(tcphdr->th_flags & TH_FIN)
        printf("FIN ");
    if(tcphdr->th_flags & TH_SYN)
        printf("SYN ");
    if(tcphdr->th_flags & TH_RST)
        printf("RST ");
    if(tcphdr->th_flags & TH_PUSH)
        printf("PUSH ");
    if(tcphdr->th_flags & TH_ACK)
        printf("ACK ");
    if(tcphdr->th_flags & TH_URG)
        printf("URG ");

    printf("}\n\n");
}