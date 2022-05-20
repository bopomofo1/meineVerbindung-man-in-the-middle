#include "../include/forward.h"
#include "../../modularity/include/init.h"
#include "../../modularity/include/ec_malloc.h"

// forwards all packets ip packets to actual ip packet destination  

void *forward(void *arg_ptr)
{
    char *errbuf = ec_mallo(PCAP_ERRBUF_SIZE);
    libnet_t *l = init_libnet_ethernet(errbuf);
    pcap_t *handle = init_pcap(errbuf);
    struct pcap_pkthdr pkthdr;

    // Receive packet
    while(1) 
    {
        u_char *packet = pcap_next(handle, (struct pcap_pkthdr *)&pkthdr);
    
        //Forward entire Ethernet packet

        // Mac-Addresses have to be changed to the real addresses
        u_char *packetModify = malloc(pkthdr.len);
        if (packetModify == NULL) 
        {
            perror("Error allocating memory\n");
            exit(EXIT_FAILURE);
        }

        memcpy(packetModify, packet, pkthdr.len);

        eth_hdr = packetModify;
        memcpy(eth_hdr->ether_dhost, pass_poison->mac2, 6);

        if(libnet_adv_write_link(l, packetModify, pkthdr.len) == -1)
            perror(libnet_geterror(l));

    }
}