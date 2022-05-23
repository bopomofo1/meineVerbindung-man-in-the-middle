/* Function to display data of a tcp packet*/

#include "../include/display_data.h"

/*
*Needs a packet with ethernet, ip and tcp header.
*Return: -1, if packet is acknowledgment
*/
    int
display_data(u_char *packet, uint size) {

    struct libnet_ipv4_hdr *iphdr = (struct libnet_ipv4_hdr *)
                           (packet + LIBNET_ETH_H);
    struct libnet_tcp_hdr *tcphdr = (struct libnet_tcp_hdr *) 
                          (packet + LIBNET_ETH_H + LIBNET_IPV4_H);

    int tcphdrLength = (tcphdr->th_off) * 4;

    if (tcphdr->th_flags == TH_ACK)
        return -1; 

    printf("%s: ", inet_ntoa(iphdr->ip_src));

    u_char *data =  packet + LIBNET_ETH_H + LIBNET_IPV4_H + tcphdrLength;
    for (int i = 0; i < size - (LIBNET_ETH_H + LIBNET_IPV4_H + tcphdrLength); i++) {
        printf("%c", *(data + i));
    }
    printf("\n");
    return 0;

}