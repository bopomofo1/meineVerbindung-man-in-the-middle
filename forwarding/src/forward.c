#include "../include/forward.h"
#include "../include/compare_mac.h"
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
    libnet_t *l = init_libnet_ethernet(errbuf);
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

        // If the source mac is our own mac, we probably already forwarded
        if (compare_mac(ethhdr->ether_shost, ownMac))
            continue;

        // Mac-destination-address has to be changed to the real address
        if (compare_mac(ethhdr->ether_shost, data_pass->mac1))
            memcpy((void *)ethhdr->ether_dhost, (void *)data_pass->mac2, 6);

        else if (compare_mac(ethhdr->ether_shost, data_pass->mac2))
            memcpy((void *)ethhdr->ether_dhost, (void *)data_pass->mac1, 6);

        else
            continue;

        // Mac-source-address has to be changed to our own mac
        memcpy((void *)ethhdr->ether_shost, (void *)ownMac, 6);


        if(libnet_adv_write_link(l, packetModify, pkthdr.len) == -1)
            fatal(libnet_geterror(l), "forward.c, line 33");
    }
}