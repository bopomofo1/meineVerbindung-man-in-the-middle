#include "header/arp.h"

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
        (uint8_t *)&targetIP,
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

int arp_reply(uint32_t senderIP, uint32_t targetIP, uint8_t *targetMac, libnet_t *l) 
{
    uint32_t ownIP;
    struct libnet_ether_addr *ownMac;

    ownMac = libnet_get_hwaddr(l);
    if(ownMac == NULL)
        libnet_fatal(libnet_geterror(l));

    
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
        libnet_fatal(libnet_geterror(l));
    

    // Build ETHERNET-Packet
    if(libnet_autobuild_ethernet((const uint8_t *)targetMac, ETHERTYPE_ARP, l) == -1)
        libnet_fatal(libnet_geterror(l));

    // Send
    if(libnet_write(l) == -1)
        libnet_fatal(libnet_geterror(l));

    libnet_clear_packet(l);
}

int arp_receive(pcap_t *handle, uint32_t senderIP, uint8_t *sender_mac)
{
    
    struct pcap_pkthdr hdr;
    const u_char *packet;
    struct bpf_program filter;      
    uint32_t *ip_ptr;
    struct ether_arp *arphdr;
    
    {
        packet = pcap_next(handle, (struct pcap_pkthdr *)&hdr);
        arphdr = (struct ether_arp *)(packet + ETH_HLEN);
        uint32_t *ip_ptr = (uint32_t *)arphdr->arp_spa;      
        if(ntohs(arphdr->ea_hdr.ar_op) == ARPOP_REPLY && ntohs(arphdr->ea_hdr.ar_hrd) == ARPHRD_ETHER && ntohs(arphdr->ea_hdr.ar_pro) == 0x800 && *ip_ptr == senderIP)
        {
                printf("MAC-Adresse ist %02x:%02x:%02x:%02x:%02x:%02x\n", arphdr->arp_sha[0], arphdr->arp_sha[1], arphdr->arp_sha[2], arphdr->arp_sha[3], arphdr->arp_sha[4], arphdr->arp_sha[5]);
                memcpy((void *) sender_mac , (const void *) arphdr->arp_sha, 6);
                return 0;
        }
        return -1;
    }
}   
