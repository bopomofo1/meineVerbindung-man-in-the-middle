#include <libnet.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include "../../modularity/include/error.h"

// To pass data to thread
struct poison_pass
{
    uint8_t *mac1;
    uint8_t *mac2;
    uint32_t ip1;
    uint32_t ip2;
    libnet_t *l;

};

int arp_request(in_addr_t targetIP, libnet_t *l);

int arp_receive(pcap_t *handle, uint32_t senderIP, uint8_t *sender_mac);

int arp_reply(uint32_t senderIP, uint32_t targetIP, uint8_t *targetMac, libnet_t *l); 

void *arp_poison(void *arg_ptr);
