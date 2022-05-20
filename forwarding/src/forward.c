#include "../include/forward.h"
#include "../../modularity/include/init.h"
#include "../../modularity/include/ec_malloc.h"
#include "../../modularity/include/thread_data_pass.h"


// forwards all packets ip packets to actual ip packet destination  

    void *
forward(void *arg_ptr) {
    char *errbuf = ec_malloc(PCAP_ERRBUF_SIZE);
    libnet_t *l = init_libnet_ethernet(errbuf);
    pcap_t *handle = init_pcap(errbuf);
    struct pcap_pkthdr pkthdr;
    struct data_pass *data_pass = (struct data_pass *)arg_ptr;

    // Receive packet
    while(1) 
    {
        u_char *packet = pcap_next(handle, (struct pcap_pkthdr *)&pkthdr);

        // Forward entire Ethernet packet

        struct libnet_ethernet_hdr *ethhdr = packet;
    
        // Mac-destination-address has to be changed to the real address
        u_char *packetModify = ec_malloc(pkthdr.len);
        memcpy(packetModify, packet, pkthdr.len);

        ethhdr = packetModify;
        memcpy(ethhdr->ether_dhost, data_pass->mac2, 6);

        if(libnet_adv_write_link(l, packetModify, pkthdr.len) == -1)
            fatal(libnet_geterror(l), "forward.c, line 33");
    }
}