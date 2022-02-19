#include "header/arp.h"
#include <pcap.h>
#include "header/hacking.h"

//void set_packet_filter(pcap_t *pcap_handle);

int main()
{
    libnet_t *l;
    pcap_t *handle;
    pcap_if_t *ift;

    u_char errbuf[LIBNET_ERRBUF_SIZE];

    l = libnet_init(LIBNET_LINK, NULL, errbuf);
    if(l == NULL)
        libnet_fatal(libnet_geterror(l));
    
     // Get device name
    if(pcap_findalldevs(&ift, (char *)(&errbuf)) == -1)
        fatal("finding devices");
    

    printf("Device is %s\n", ift->name);
    

     /* Open device for live capture */

     handle = pcap_open_live(ift->name, 4096, 1, 100, errbuf);
     if(handle == NULL)
        fatal("opening live session");
    
    // Set packet filter for incoming ARP-Packets
    set_packet_filter(handle);

    // Request
    printf("[ ]sending ARP-request...\n");
    arp_request(libnet_name2addr4(l, "192.168.5.193", LIBNET_DONT_RESOLVE), l);
    printf("[X]ARP-request sent\n");

    // Receive
    printf("[ ]searching for ARP-reply...\n");
    arp_receive(handle);
    printf("[X]ARP-reply received\n");
   
}

void set_packet_filter(pcap_t *handle)
{
    struct bpf_program filter;
    char filter_string[200];
    sprintf(filter_string, "arp");
    printf("[DEBUG] filter string is %s\n", filter_string);

    if(pcap_compile(handle, &filter, filter_string, 0, 0) == -1)
    {
        perror("compile filter error");
        exit(EXIT_FAILURE);
    }

    if(pcap_setfilter(handle, &filter) == -1)
    {
        perror("setting filter error");
        exit(EXIT_FAILURE);
    }

}