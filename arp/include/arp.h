#include <libnet.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include "../../modularity/include/error.h"
#include "../../modularity/include/data_pass.h"


    int 
arp_request(in_addr_t targetIP, libnet_t *l);

    int 
arp_receive(pcap_t *handle, uint32_t senderIP, uint8_t *sender_mac);

    int 
arp_reply(uint32_t senderIP, uint32_t targetIP, uint8_t *targetMac, libnet_t *l); 

    void *
arp_poison(void *arg_ptr);
