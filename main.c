#include "header/arp.h"
#include <pcap.h>
#include "header/hacking.h"

void set_packet_filter(pcap_t *handle);

void usage(char* name)
{
    printf("Usage: %s <IP of Target A> <IP of Target B>\n", name);
    exit(0);
}

int main(int argc, char *argv[])
{
    libnet_t *l;
    pcap_t *handle;
    pcap_if_t *ift;

    u_char errbuf[LIBNET_ERRBUF_SIZE];

    uint32_t target1_ip;
    uint32_t target2_ip;

    if(argc < 3)
        usage(argv[0]);

    l = libnet_init(LIBNET_LINK, NULL, errbuf);
    if(l == NULL)
        libnet_fatal(libnet_geterror(l));
    
    // Get device name
    if(pcap_findalldevs(&ift, (char *)(&errbuf)) == -1)
        fatal("finding devices");
    
    // Convert Targets ASCII-IP's to Numbers
    if(((target1_ip = libnet_name2addr4(l, argv[1], LIBNET_DONT_RESOLVE)) ==  -1) 
    || ((target2_ip = libnet_name2addr4(l, argv[2], LIBNET_DONT_RESOLVE)) ==  -1))
        fatal(libnet_geterror(l));
    
    

    printf("Device is %s\n", ift->name);
    

     /* Open device for live capture */
     handle = pcap_open_live(ift->name, 4096, 1, 100, errbuf);
     if(handle == NULL)
        fatal("opening live session");
    
    // Set packet filter for incoming ARP-Packets
    set_packet_filter(handle);
    
    // Request Target 1
    printf("\nTarget #1: sending ARP-requests... \n");
    arp_request(target1_ip, l);
    // Receive Target 1
    printf("Target #1: searching for ARP-replys...\n");
    arp_receive(handle, target1_ip);

    printf("\n-------------------------------\n\n");

    // Request Target 2
    printf("Target #2: sending ARP-requests... \n");
    arp_request(target2_ip, l);
    // Receive Target 2
    printf("Target #2: searching for ARP-replys...\n");
    arp_receive(handle, target2_ip);


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