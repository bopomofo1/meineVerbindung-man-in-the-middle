#include <libnet.h>
#include <pcap.h>
#include <sys/socket.h>

void libnet_fatal(const char* msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

int arp_request(in_addr_t targetIP, libnet_t *l)
{
    struct libnet_ether_addr broadcastMac;
    struct libnet_ether_addr *ownMac;
    struct libnet_ether_addr targetMac;
    in_addr_t ownIP;

    for(int i = 0; i < 6; i++) 
    {
        broadcastMac.ether_addr_octet[i] = 0xff;
        targetMac.ether_addr_octet[i] = 0x00;
    }

    ownMac = libnet_get_hwaddr(l);
    ownIP = libnet_get_ipaddr4(l);
    if(ownMac == NULL || ownIP == -1)
        libnet_fatal(libnet_geterror(l));
    
    /* Send ARP-Request */

    // Build ARP-Packet
    if (libnet_autobuild_arp
    (
        ARPOP_REQUEST, 
        (const uint8_t *)&ownMac->ether_addr_octet, 
        (const uint8_t *)&ownIP,
        (const uint8_t *)&targetMac.ether_addr_octet,
        (const uint8_t *)&targetIP,
        l
    )
        == -1
    )
        libnet_fatal(libnet_geterror(l));
    

    // Build ETHERNET-Packet
    if(libnet_autobuild_ethernet((const uint8_t *)&broadcastMac.ether_addr_octet, ETHERTYPE_ARP, l) == -1)
        libnet_fatal(libnet_geterror(l));

    // Send
    if(libnet_write(l) == -1)
        libnet_fatal(libnet_geterror(l));
    
}