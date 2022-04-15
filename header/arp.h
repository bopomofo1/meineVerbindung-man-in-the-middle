#include <pcap.h>
#include <libnet.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <stdlib.h>



void libnet_fatal(const char* msg);

int arp_request(in_addr_t targetIP, libnet_t *l);

int arp_reply(uint32_t senderIP, uint32_t targetIP, uint8_t *targetMac, libnet_t *l);

/**
 * Looks into the first packet found by pcap_next and checks wether it comes from senderIP or not.
 * If it is from senderIP then the sender's mac will be written to sender_mac*
 * Also prints the found mac
 * @param pcap_t pointer to a pcap handle
 * @param uint32_t IP from the sender of the ARP-packet
 * @param uint8_t* Pointer to an allocated seqence of 6 Bytes. The sender's mac address will be written into this.
 * @retval 0 on Success
 */
int arp_receive(pcap_t *handle, uint32_t senderIP, uint8_t *sender_mac);

void * arp_poison_thread(void *arg_ptr);