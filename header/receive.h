#include <pcap.h>
#include <libnet.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <stdlib.h>

struct packet_node 

{
    uint32_t seq;
    uint32_t ack;
    struct packet_node *next_packet_node;
};

void print_packets(struct packet_node *head);

void push_packet_node(struct packet_node *head, uint32_t seq, uint32_t ack);

int search_packets(struct packet_node *head, uint32_t seq, uint32_t ack);

void set_packet_filter(pcap_t *handle, char *filter_opt);

void decode_ip(struct libnet_ipv4_hdr *iphdr);

void decode_tcp(struct libnet_tcp_hdr *tcphdr);
