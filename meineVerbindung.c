
#include <gtk/gtk.h>
#include <libnet.h>
#include "modularity/include/error.h"
#include "modularity/include/ec_malloc.h"
#include "modularity/include/init.h"
#include "arp/include/arp.h"
#include "start/include/start.h"
#include "inject/include/inject.h"


    int 
main (int argc, char *argv[]) {
    GError *error = NULL;
    GtkBuilder *builder;
    GtkWidget *window;
    GtkEntry *ip1Entry, *ip2Entry;
    GtkEntry *ip1SendEntry, *ip2SendEntry;
    GtkButton *startBtn, *ip1SendBtn, *ip2SendBtn;
    GtkTextView *statusTextview;
    GtkTextView *chatTextview;

    gtk_init (&argc, &argv);

    builder = gtk_builder_new ();
    if (gtk_builder_add_from_file (builder, "UI/glade.ui", &error) == 0) {
      g_printerr ("Error loading file: %s\n", error->message);
      g_clear_error (&error);
      return 1;
    }

    window = gtk_builder_get_object (builder, "window");
    g_signal_connect (window, "destroy", G_CALLBACK (gtk_main_quit), NULL);
    gtk_window_set_title (GTK_WINDOW(window), "meineVerbindung");
    gtk_window_set_default_size (GTK_WINDOW(window), 500, 400);
    gtk_window_set_position (GTK_WINDOW(window), GTK_WIN_POS_CENTER);

    // Load objects from ui file
    ip1Entry = gtk_builder_get_object (builder, "ip1");
    ip2Entry = gtk_builder_get_object (builder, "ip2");
    startBtn = gtk_builder_get_object (builder, "start");
    ip1SendBtn = gtk_builder_get_object (builder, "ip1SendBtn");
    ip2SendBtn = gtk_builder_get_object (builder, "ip2SendBtn");
    statusTextview = gtk_builder_get_object (builder, "status");
    chatTextview  = gtk_builder_get_object (builder, "chat");
    ip1SendEntry  = gtk_builder_get_object (builder, "ip1SendEntry");
    ip2SendEntry  = gtk_builder_get_object (builder, "ip2SendEntry");

    // Load CSS
    GtkCssProvider *cssProvider = gtk_css_provider_new();
    gtk_css_provider_load_from_path(cssProvider, "CSS/theme.css", NULL);
    gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
                               GTK_STYLE_PROVIDER(cssProvider),
                               GTK_STYLE_PROVIDER_PRIORITY_USER);

    // This data gets passed to different functions
    struct DataPass *startData = malloc(sizeof(struct DataPass));
    startData->canInject = 0;
    startData->ip1Entry = ip1Entry;
    startData->ip2Entry = ip2Entry;
    startData->ip1SendEntry = ip1SendEntry;
    startData->ip2SendEntry = ip2SendEntry;
    startData->statusView = statusTextview;
    startData->chatView = chatTextview;

    g_signal_connect (startBtn, "clicked", G_CALLBACK (start), startData);
    g_signal_connect (ip1SendBtn, "clicked", G_CALLBACK (send1), startData);
    g_signal_connect (ip2SendBtn, "clicked", G_CALLBACK (send2), startData);
    

    gtk_widget_show_all (window);
    gtk_main ();

    return 0;

}