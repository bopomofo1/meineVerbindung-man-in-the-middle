// contains functions to initialise libnet or pcap

#include "../include/init.h"

   libnet_t* 
init_libnet_ipv4(char *errbuf) {
    libnet_t *l = libnet_init(LIBNET_RAW4, NULL, errbuf);
    if(l == NULL)
        fatal(libnet_geterror(l), "init.c, line 7");   
}

/* 
*initialises libnet with injection type LIBNET_LINK_ADV 
*to send ethernet packets.
*Returns NULL on error and outputs error message
*/
    libnet_t* 
init_libnet_ethernet(char *errbuf) {
    libnet_t *l = libnet_init(LIBNET_LINK_ADV, NULL, errbuf);
    if(l == NULL)
        fatal(libnet_geterror(l), "init.c, line 18");   
}


/*
*Initialises pcap in promicious mode.
*Finds networkdevice automatically,
could become an issue.
* Writes errors to Errbuf (size 256)
*/
    pcap_t*
init_pcap(char *errbuf) {
    pcap_t *handle;	// Session handle               
    pcap_if_t *ift; // Pcap interface to retrieve network device
    
    // Get device name
    if(pcap_findalldevs(&ift, (char *)(&errbuf)) == -1)
        fatal("searching for network devices", "init.c, line 37");

     handle = pcap_open_live(ift->name, BUFSIZ, 1, 300, errbuf);
     if(handle == NULL)
        fatal(pcap_geterr(handle), "init.c, line 40");
}