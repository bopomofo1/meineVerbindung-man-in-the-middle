#include <libnet.h>
#include <pcap.h>


struct poison_pass
{
    libnet_t* l;
    uint32_t target1_ip, target2_ip;
    uint8_t *target1_mac, *target2_mac;

};

void libnet_fatal(const char* msg);

int arp_request(in_addr_t targetIP, libnet_t *l);

/**
 * Looks into the first packet found by pcap_next and checks wether it comes from senderIP or not.
 * If it is from senderIP then the sender's mac will be written to sender_mac*.    
 * Also prints the found mac
 * @param pcap_t pointer to a pcap handle
 * @param uint32_t IP from the sender of the ARP-packet
 * @param uint8_t* Pointer to an allocated seqence of 6 Bytes. The sender's mac address will be written into this.
 * @retval 0 on Success
 */
int arp_receive(pcap_t *handle, uint32_t senderIP, uint8_t *sender_mac);

int arp_reply(uint32_t senderIP, uint32_t targetIP, uint8_t *targetMac, libnet_t *l); 