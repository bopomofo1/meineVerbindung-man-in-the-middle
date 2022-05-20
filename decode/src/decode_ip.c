#include "../header/decode.h"

// Prints information of ip header

void decode_ip(struct libnet_ipv4_hdr *iphdr)
{
    printf("\t(( Layer 3 ::: IP Header ))\n");
    struct in_addr ip_address;
    ip_address = iphdr->ip_src;
    printf("\t( Source: %s\tDestination: ", inet_ntoa(ip_address));
    ip_address = iphdr->ip_dst;
    printf("%s )\n", inet_ntoa(ip_address));
}