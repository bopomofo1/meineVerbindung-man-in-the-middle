
#include "../../decode/include/display_data.h"
#include "../include/forward.h"
#include "../include/compare_mac.h"
#include "../include/send_tcp.h"
#include "../../modularity/include/init.h"
#include "../../modularity/include/ec_malloc.h"
#include "../../modularity/include/thread_data_pass.h"


/*
*Forwards all ethernet packets to mac1 or mac2, even 
*if they are actually directed to us
*/

    void *
forward(void *arg_ptr) {
    char *errbuf = ec_malloc(PCAP_ERRBUF_SIZE);
    libnet_t *l = init_libnet_ipv4(errbuf);
    pcap_t *handle = init_pcap(errbuf);
    struct pcap_pkthdr pkthdr;
    struct data_pass *data_pass = (struct data_pass *)arg_ptr;
    uint8_t *ownMac = libnet_get_hwaddr(l);
    if (ownMac == NULL)
        fatal(libnet_geterror(l), "forward.c, line 20");


    // Receive packet
    while(1) 
    {
        u_char *packet = pcap_next(handle, (struct pcap_pkthdr *)&pkthdr);
        u_char *packetModify = ec_malloc(pkthdr.len);
        memcpy(packetModify, packet, pkthdr.len);
        struct libnet_ethernet_hdr *ethhdr = packetModify;
        struct libnet_ipv4_hdr *iphdr = packetModify + LIBNET_ETH_H;
        struct libnet_tcp_hdr *tcphdr = packetModify + LIBNET_ETH_H + LIBNET_IPV4_H;
        int tcpHeaderLength = tcphdr->th_off * 4;
        char *data = packet + LIBNET_ETH_H + LIBNET_IPV4_H + tcpHeaderLength;
        int dataLen = pkthdr.len - LIBNET_ETH_H - LIBNET_IPV4_H - tcpHeaderLength;
        
        // If the source mac is our own mac, we probably already forwarded
        if (compare_mac(ethhdr->ether_shost, ownMac))
            continue;

        // Check where the packet came from
        if (compare_mac(ethhdr->ether_shost, data_pass->mac1)) {
            if (ethhdr->ether_type == htons(ETHERTYPE_IP) 
                && iphdr->ip_p == IPPROTO_TCP) {
                memcpy(data_pass->header1, packetModify, pkthdr.len);
                // Translate seq and ack
                tcphdr->th_seq = htonl(ntohl(tcphdr->th_seq) - *data_pass->dataSentByUs1);
                tcphdr->th_ack = htonl(ntohl(tcphdr->th_ack) - *data_pass->dataSentByUs2);
            }
        }

        else if (compare_mac(ethhdr->ether_shost, data_pass->mac2)) {
            if (ethhdr->ether_type == htons(ETHERTYPE_IP) 
                && iphdr->ip_p == IPPROTO_TCP) {
                memcpy(data_pass->header2, packet, pkthdr.len);
                // Translate seq and ack
                tcphdr->th_seq = htonl(ntohl(tcphdr->th_seq) - *data_pass->dataSentByUs2);
                tcphdr->th_ack = htonl(ntohl(tcphdr->th_ack) - *data_pass->dataSentByUs1);
            }
        }

        else
            continue;

        if (ethhdr->ether_type == htons(ETHERTYPE_IP) 
            && iphdr->ip_p == IPPROTO_TCP) {
            if (display_data(packetModify, pkthdr.len) == -1) {
                send_tcp(l, tcphdr->th_seq, tcphdr->th_ack, packetModify, data, dataLen);
                continue;
            }
            printf("Forward? [y/n]: \n");
            char input[1];
            fgets(input, 1, stdin);
            if (input[0] == 'y')
                printf("forwarding!!!\n");
            send_tcp(l, tcphdr->th_seq, tcphdr->th_ack, packetModify, data, dataLen);
        }

    }
}