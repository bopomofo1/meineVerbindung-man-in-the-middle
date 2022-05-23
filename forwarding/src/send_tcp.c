// Contains a function to sent a tcp packet withlibnet

#include <libnet.h>
#include <pcap.h>

/*
*header: contains all headers starting from ethernet header
*seq: big endian
*ack: big endian
*/

    int
send_tcp(libnet_t *l, int seq, int ack, char *header, char *data, int dataLen) {

    struct libnet_ipv4_hdr *iphdr = header + LIBNET_ETH_H;
    struct libnet_tcp_hdr *tcphdr = header + LIBNET_ETH_H + LIBNET_IPV4_H;

    int tcpTag = libnet_build_tcp (
                ntohs(tcphdr->th_sport),
                ntohs(tcphdr->th_dport),
                ntohl(seq),
                ntohl(ack),
                tcphdr->th_flags,
                ntohs(tcphdr->th_win),
                0,
                NULL,
                LIBNET_TCP_H + dataLen,
                data,
                dataLen,
                l,
                0);

        if (tcpTag == -1)
            fatal(libnet_geterror(l), "send_tcp.c, line x");
            
        int ipTag = libnet_build_ipv4 (
            LIBNET_IPV4_H + LIBNET_TCP_H + dataLen,/* length */
            0,                                         /* TOS */
            ntohs(iphdr->ip_id),                       /* IP ID */
            0,                                         /* IP Frag */
            iphdr->ip_ttl,                             /* TTL */
            IPPROTO_TCP,                               /* protocol */
            0,                                         /* checksum */
            iphdr->ip_src.s_addr,                      /* source IP */
            iphdr->ip_dst.s_addr,                      /* destination IP */
            NULL,                                      /* payload */
            0,                                         /* payload size */
            l,                                         /* libnet handle */
            0); 

            if (ipTag == -1)
                fatal(libnet_geterror(l), "send_tcp.c, line x");

            if (libnet_write(l) == -1)
                fatal(libnet_geterror(l), "send_tcp.c, line x");

            libnet_clear_packet(l);
}