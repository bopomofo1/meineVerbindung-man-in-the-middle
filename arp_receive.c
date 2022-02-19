#include <stdlib.h>
#include <pcap.h>
#include <libnet.h>
#include <netinet/if_ether.h>

int arp_receive(pcap_t *handle, uint8_t mac[6])
{
    
    struct pcap_pkthdr hdr;
    const u_char *packet;
    struct bpf_program filter;
    struct in_addr target;
    struct ether_arp *arphdr;

    for(int i = 0; i < 5000; i++)
    {
        packet = pcap_next(handle, (struct pcap_pkthdr *)&hdr);
        arphdr = packet + ETH_HLEN;
        target.s_addr = arphdr->arp_spa;
       // printf("[source IP] %s\n", inet_ntoa(target));
        
        if(ntohs(arphdr->ea_hdr.ar_op) == ARPOP_REPLY && ntohs(arphdr->ea_hdr.ar_hrd) == ARPHRD_ETHER && ntohs(arphdr->ea_hdr.ar_pro) == 0x800)
        {
                printf("received arp packet\n");
                printf("mac address is %02x:%02x:%02x:%02x:%02x:%02x\n", arphdr->arp_sha[0], arphdr->arp_sha[1], arphdr->arp_sha[2], arphdr->arp_sha[3], arphdr->arp_sha[4], arphdr->arp_sha[5]);

        }
    }
}