#include <libnet.h>
#include <pcap.h>
    
    int
send_tcp(libnet_t *l, int seq, int ack, char *header, char *data, int dataLen);