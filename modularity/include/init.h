#include <libnet.h>
#include <pcap.h>

 libnet_t* 
init_libnet_ipv4(char *errbuf);

    libnet_t* 
init_libnet_ethernet(char *errbuf);

    pcap_t*
init_pcap(char *errbuf);
