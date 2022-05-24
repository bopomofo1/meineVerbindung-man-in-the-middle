// Structs to pass data to another thread

#pragma once

#include <libnet.h>
#include <gtk/gtk.h>



    struct 
DataPass {
    uint8_t *mac1;
    uint8_t *mac2;
    uint32_t ip1;
    uint32_t ip2;
    libnet_t *l;
    uint32_t *dataSentByUs1, *dataSentByUs2;
    u_char *header1, *header2;
    GtkEntry *ip1Entry, *ip2Entry;
    GtkTextView *statusView, *chatView;
};