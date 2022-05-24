
#include <gtk/gtk.h>
#include <libnet.h>
#include "modularity/include/error.h"
#include "modularity/include/ec_malloc.h"
#include "modularity/include/init.h"
#include "arp/include/arp.h"

    struct 
startDataPass {
    GtkEntry *ip1Entry, *ip2Entry;
    GtkTextView *statusView, *chatView;
};

    static void
start(GtkWidget *widget, gpointer data) {
    struct startDataPass *dataPass = data;
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
    buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(dataPass->statusView));

    gtk_text_buffer_create_tag(buffer, "gap",
        "pixels_above_lines", 30, NULL);

    gtk_text_buffer_create_tag(buffer, "lmarg", 
        "left_margin", 5, NULL);
    gtk_text_buffer_create_tag(buffer, "blue_fg", 
        "foreground", "blue", NULL); 
    gtk_text_buffer_create_tag(buffer, "gray_bg", 
        "background", "gray", NULL); 
    gtk_text_buffer_create_tag(buffer, "italic", 
        "style", PANGO_STYLE_ITALIC, NULL);
    gtk_text_buffer_create_tag(buffer, "bold", 
        "weight", PANGO_WEIGHT_BOLD, NULL);

    gtk_text_buffer_get_iter_at_offset(buffer, &iter, 0);

    gtk_text_buffer_insert(buffer, &iter, "Plain text\n", -1);
    gtk_text_buffer_insert_with_tags_by_name(buffer, &iter, 
            "Colored Text\n", -1, "blue_fg", "lmarg",  NULL);
    gtk_text_buffer_insert_with_tags_by_name (buffer, &iter, 
            "Text with colored background\n", -1, "lmarg", "gray_bg", NULL);

    gtk_text_buffer_insert_with_tags_by_name (buffer, &iter, 
            "Text in italics\n", -1, "italic", "lmarg",  NULL);

    gtk_text_buffer_insert_with_tags_by_name (buffer, &iter, 
            "Bold text\n", -1, "bold", "lmarg",  NULL);

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
        return;
    }                                  
    else if (target1Ip  ==  -1)  {
        gtk_entry_set_text (dataPass->ip1Entry, "");
        gtk_entry_set_placeholder_text (dataPass->ip1Entry, "ungültige IP-Adresse");
        return;
    }
    else if (target2Ip  ==  -1)  {
        gtk_entry_set_placeholder_text (dataPass->ip2Entry, "ungültige IP-Adresse");
        gtk_entry_set_text (dataPass->ip2Entry, "");
        return;
    }

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
}

    int 
main (int argc, char *argv[]) {
    GError *error = NULL;
    GtkBuilder *builder;

    GtkWidget *window;
    GtkEntry *ip1Entry, *ip2Entry;
    GtkButton *startBtn;
    GtkTextView *statusTextview, *chatTextview;

    gtk_init (&argc, &argv);

    builder = gtk_builder_new ();
    if (gtk_builder_add_from_file (builder, "glade.ui", &error) == 0) {
      g_printerr ("Error loading file: %s\n", error->message);
      g_clear_error (&error);
      return 1;
    }
    window = gtk_builder_get_object (builder, "window");
    g_signal_connect (window, "destroy", G_CALLBACK (gtk_main_quit), NULL);

    gtk_window_set_title (GTK_WINDOW(window), "meineVerbindung");
    gtk_window_set_default_size (GTK_WINDOW(window), 500, 400);
    gtk_window_set_position (GTK_WINDOW(window), GTK_WIN_POS_CENTER);

    ip1Entry = gtk_builder_get_object (builder, "ip1");
    ip2Entry = gtk_builder_get_object (builder, "ip2");
    startBtn = gtk_builder_get_object (builder, "start");

    statusTextview = gtk_builder_get_object (builder, "status");

    GtkCssProvider *cssProvider = gtk_css_provider_new();
    gtk_css_provider_load_from_path(cssProvider, "theme.css", NULL);
    gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
                               GTK_STYLE_PROVIDER(cssProvider),
                               GTK_STYLE_PROVIDER_PRIORITY_USER);

    struct startDataPass *startData = malloc(sizeof(struct startDataPass));
    startData->ip1Entry = ip1Entry;
    startData->ip2Entry = ip2Entry;
    startData->statusView = statusTextview;
    g_signal_connect (startBtn, "clicked", G_CALLBACK (start), startData);

    gtk_widget_show_all (window);
    gtk_main ();

    return 0;

}