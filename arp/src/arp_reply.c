#include "../include/arp.h"


// sends an ARP-Reply with the own MAC as the source-address
int arp_reply(uint32_t senderIP, uint32_t targetIP, uint8_t *targetMac, libnet_t *l) 
{
    uint32_t ownIP;
    struct libnet_ether_addr *ownMac;

    ownMac = libnet_get_hwaddr(l);
    if(ownMac == NULL)
        fatal(libnet_geterror(l), "arp_reply.c, line 12");

    
    /* Send ARP-Request */

    // Build ARP-Packet
    if (libnet_autobuild_arp
    (
        ARPOP_REPLY, 
        (const uint8_t *)&ownMac->ether_addr_octet, 
        (const uint8_t *)&senderIP,
        (const uint8_t *)targetMac,
        (uint8_t *)&targetIP,
        l
    )
        == -1
    )
        fatal(libnet_geterror(l), "arp_reply.c, line 18");
    

    // Build ETHERNET-Packet
    if(libnet_autobuild_ethernet((const uint8_t *)targetMac, ETHERTYPE_ARP, l) == -1)
        fatal(libnet_geterror(l), "arp_reply.c, line 33");

    // Send
    if(libnet_write(l) == -1)
        fatal(libnet_geterror(l), "arp_reply.c, line 37");

    libnet_clear_packet(l);
}