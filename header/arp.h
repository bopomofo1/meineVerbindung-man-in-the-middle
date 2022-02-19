#include <libnet.h>
#include <pcap.h>

void libnet_fatal(const char* msg);
int arp_request(in_addr_t targetIP, libnet_t *l);
int arp_receive(pcap_t *handle, uint32_t senderIP);

