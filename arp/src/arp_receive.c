#include "../include/arp.h"


/**
 * Looks into the first packet found by pcap_next and checks wether it comes from senderIP or not.  
 * If it is from senderIP then the sender's mac will be written to sender_mac*  
 * Also prints the found mac  
 * @param pcap_t pointer to a pcap handle  
 * @param uint32_t IP from the sender of the ARP-packet  
 * @param uint8_t* Pointer to an allocated seqence of 6 Bytes. The sender's mac address will be written into this.  
 * @retval 0 on Success  
 */
    int 
arp_receive(pcap_t *handle, uint32_t senderIP, uint8_t *sender_mac) {
    struct pcap_pkthdr hdr;
    const u_char *packet;
    struct bpf_program filter;      
    uint32_t *ip_ptr;
    struct ether_arp *arphdr;

    {
        packet = pcap_next(handle, (struct pcap_pkthdr *)&hdr);
        arphdr = (struct ether_arp *)(packet + ETH_HLEN);
        uint32_t *ip_ptr = (uint32_t *)arphdr->arp_spa;      
        if (ntohs(arphdr->ea_hdr.ar_op) == ARPOP_REPLY 
        && ntohs(arphdr->ea_hdr.ar_hrd) == ARPHRD_ETHER 
        && ntohs(arphdr->ea_hdr.ar_pro) == 0x800 
        && *ip_ptr == senderIP) {
                printf("MAC-Adresse ist %02x:%02x:%02x:%02x:%02x:%02x\n", 
                arphdr->arp_sha[0], 
                arphdr->arp_sha[1], 
                arphdr->arp_sha[2], 
                arphdr->arp_sha[3], 
                arphdr->arp_sha[4], 
                arphdr->arp_sha[5]);
                
                memcpy((void *) sender_mac , (const void *) arphdr->arp_sha, 6);
                return 0;
        }
        return 1;
    }
}       