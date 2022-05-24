#include "../include/inject.h"

// This function gets called, when the send1 button is clicked
    void
send1(GtkWidget *widget, gpointer data) {
    struct DataPass *dataPass = data;
    char *errbuf = ec_malloc(PCAP_ERRBUF_SIZE);
    libnet_t *l = init_libnet_ipv4(errbuf);
    struct libnet_ipv4_hdr *iphdr1 = dataPass->header1 + LIBNET_ETH_H;
    struct libnet_tcp_hdr *tcphdr1 = dataPass->header1 + LIBNET_ETH_H + LIBNET_IPV4_H;
    struct libnet_ipv4_hdr *iphdr2 = dataPass->header2 + LIBNET_ETH_H;
    struct libnet_tcp_hdr *tcphdr2 = dataPass->header2 + LIBNET_ETH_H + LIBNET_IPV4_H;


    char *dataToSend = gtk_entry_get_text(dataPass->ip1SendEntry);

    send_tcp(l, tcphdr1->th_ack, tcphdr1->th_seq, dataPass->header2,
                dataToSend, strlen(dataToSend));

}


// This function gets called, when the send2 button is clicked
    void
send2(GtkWidget *widget, gpointer data) {
    struct DataPass *dataPass = data;
    char *errbuf = ec_malloc(PCAP_ERRBUF_SIZE);
    libnet_t *l = init_libnet_ipv4(errbuf);
    struct libnet_ipv4_hdr *iphdr1 = dataPass->header1 + LIBNET_ETH_H;
    struct libnet_tcp_hdr *tcphdr1 = dataPass->header1 + LIBNET_ETH_H + LIBNET_IPV4_H;
    struct libnet_ipv4_hdr *iphdr2 = dataPass->header2 + LIBNET_ETH_H;
    struct libnet_tcp_hdr *tcphdr2 = dataPass->header2 + LIBNET_ETH_H + LIBNET_IPV4_H;


    char *dataToSend = gtk_entry_get_text(dataPass->ip2SendEntry);

    send_tcp(l, tcphdr2->th_ack, tcphdr2->th_seq, dataPass->header1,
                dataToSend, strlen(dataToSend));

}
