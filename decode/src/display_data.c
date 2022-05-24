/* Function to display data of a tcp packet*/

#include "../include/display_data.h"

/*
*Needs a packet with ethernet, ip and tcp header.
*Return: -1, if packet is acknowledgment
*/
    int
display_data(u_char *packet, uint size, GtkTextView *chat) {
    

    GtkTextBuffer *buffer;
    
    GtkTextIter iter, start, end;
    buffer = gtk_text_view_get_buffer (GTK_TEXT_VIEW (chat));

    gtk_text_buffer_get_start_iter(buffer, &start);
    gtk_text_buffer_get_end_iter(buffer, &end);

    char *text = gtk_text_buffer_get_text(buffer, &start, &end, 0);
    int bufferlen = gtk_text_buffer_get_char_count(buffer);

    struct libnet_ipv4_hdr *iphdr = (struct libnet_ipv4_hdr *)
                           (packet + LIBNET_ETH_H);
    struct libnet_tcp_hdr *tcphdr = (struct libnet_tcp_hdr *) 
                          (packet + LIBNET_ETH_H + LIBNET_IPV4_H);

    int tcphdrLength = (tcphdr->th_off) * 4;

    if (tcphdr->th_flags == TH_ACK) 
        return -1; 

    char *ipStr = inet_ntoa(iphdr->ip_src);
    int ipLen =  strlen(ipStr);


    u_char *data =  packet + LIBNET_ETH_H + LIBNET_IPV4_H + tcphdrLength;
    int datalen = size - (LIBNET_ETH_H + LIBNET_IPV4_H + tcphdrLength);


    u_char *dataStr = ec_malloc(datalen + bufferlen + ipLen + strlen(": \n"));
    strcpy(dataStr, ipStr);
    strcpy(dataStr + ipLen, ": \n");

    printf("hallo\n");
    for (int i = 0; i < datalen + ipLen +  strlen(": \ns"); i++) {
        dataStr[i + ipLen +  strlen(": \n")] = *(data + i);
    }

    memcpy(dataStr + datalen + ipLen +  strlen(": \n"), text, bufferlen);
    gtk_text_buffer_set_text (buffer, dataStr, datalen + bufferlen + ipLen +  strlen(": \n"));
    free(dataStr);
    free(text);
    return 0;

}