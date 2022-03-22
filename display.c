#include "header/arp.h"
#include "header/display.h"

void * display(void *arg_ptr)
{

    struct display_pass *pass = (struct display_pass *)arg_ptr;

    pcap_t *pcap_handle = pass->handle;
    struct pcap_pkthdr pkthdr;
    u_char *packet;
    struct libnet_tcp_hdr *tcp_hdr;
    
    while(1)
    {
        packet = pcap_next(pcap_handle, &pkthdr);
        printf("got %d bytes packet\n", pkthdr.len);
        tcp_hdr = (struct libnet_tcp_hdr *)(packet + LIBNET_ETH_H + LIBNET_IPV4_H);
        if(pkthdr.len == 0) continue;

        // Print TCP info
        unsigned int a = ntohl(tcp_hdr->th_seq);
        printf("seq: %x\n", a);

        /*
        fflush(stdout);
            
        for(int i = 0; i < pkthdr.len; i++)
        {
            if(*(packet + i) < 31 || *(packet + i) > 127) // non printable characters
                printf(".");
            else
                printf("%c", *(packet + i));
        }
        printf("\n");
        //fflush(stdout);
        */
        
    }
    
}

void set_packet_filter(pcap_t *handle, char *filter_opt)
{
    struct bpf_program filter;
    char filter_string[200];
    strncpy(filter_string, filter_opt, 200);
    printf("[DEBUG] filter string ist %s\n", filter_string);

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