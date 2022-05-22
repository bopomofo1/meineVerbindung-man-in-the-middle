#include "../include/inject.h"

// Function to inject data from commandline
    void *
inject(void *arg_ptr) {

    char errbuf[LIBNET_ERRBUF_SIZE];
    struct data_pass *data_pass = arg_ptr;
    libnet_t *l = init_libnet_ipv4(errbuf);
    struct libnet_ipv4_hdr *iphdr1 = data_pass->header1 + LIBNET_ETH_H;
    struct libnet_tcp_hdr *tcphdr1 = data_pass->header1 + LIBNET_ETH_H + LIBNET_IPV4_H;
    struct libnet_ipv4_hdr *iphdr2 = data_pass->header2 + LIBNET_ETH_H;
    struct libnet_tcp_hdr *tcphdr2 = data_pass->header2 + LIBNET_ETH_H + LIBNET_IPV4_H;


    while (1) {
        char str[100];
        fgets(str, 100, stdin);
        printf("%s", str);

        libnet_seed_prand(l);
        int tcpTag = libnet_build_tcp (
            ntohs(tcphdr1->th_sport),
            ntohs(tcphdr1->th_dport),
            ntohl(tcphdr2->th_ack),
            ntohl(tcphdr1->th_ack),
            TH_PUSH | TH_ACK,
            libnet_get_prand(LIBNET_PRu16),
            0,
            NULL,
            LIBNET_TCP_H + strlen(str),
            str,
            strlen(str),
            l,
            0);
        if (tcpTag == -1)
            fatal(libnet_geterror(l), "inject.c, line 16");
        
        int ipTag = libnet_build_ipv4 (
            LIBNET_IPV4_H + LIBNET_TCP_H + strlen(str), /* length */
            0,                       /* TOS */
            libnet_get_prand(LIBNET_PRu16),                     /* IP ID */
            0,                       /* IP Frag */
            64,                      /* TTL */
            IPPROTO_TCP,             /* protocol */
            0,                       /* checksum */
            iphdr1->ip_src.s_addr,    /* source IP */
            iphdr1->ip_dst.s_addr,    /* destination IP */
            NULL,                    /* payload */
            0,                       /* payload size */
            l,                       /* libnet handle */
            0); 
        if (ipTag == -1)
            fatal(libnet_geterror(l), "inject.c, line 37");

        if (libnet_write(l) == -1)
            fatal(libnet_geterror(l), "inject.c, line 56");
        
        data_pass->dataSentByUs1 += strlen(str);

    }
}