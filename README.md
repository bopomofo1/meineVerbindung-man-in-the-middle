host1 chats unencrypted with host2 in a local network.
This projects aim was to get between host1 and host2 to see their messages, but also to craft fake messages from host1 to send them to host2 or the other way around.
The mitm gets done via ARP-Poisoning.
After sending a fake message, further messages get translated, because host1 and host2 are out of sync.
