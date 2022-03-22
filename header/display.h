
void * display(void *arg_ptr);

void set_packet_filter(pcap_t *handle, char *filter_opt);

struct display_pass 
{
    pcap_t* handle;
    struct libnet_tcp_hdr *tcp_header;
    struct libnet_ipv4_hdr *ip_header;
};

