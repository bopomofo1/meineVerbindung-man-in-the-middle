
#include <gtk/gtk.h>
#include <libnet.h>
#include "modularity/include/error.h"
#include "modularity/include/ec_malloc.h"
#include "modularity/include/init.h"
#include "arp/include/arp.h"
#include "start/include/start.h"


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
    statusTextview = gtk_builder_get_object (builder, "status");
    chatTextview  = gtk_builder_get_object (builder, "chat");

    // Load CSS
    GtkCssProvider *cssProvider = gtk_css_provider_new();
    gtk_css_provider_load_from_path(cssProvider, "CSS/theme.css", NULL);
    gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
                               GTK_STYLE_PROVIDER(cssProvider),
                               GTK_STYLE_PROVIDER_PRIORITY_USER);

    // This data gets passed to different functions
    struct DataPass *startData = malloc(sizeof(struct DataPass));
    startData->ip1Entry = ip1Entry;
    startData->ip2Entry = ip2Entry;
    startData->statusView = statusTextview;
    g_signal_connect (startBtn, "clicked", G_CALLBACK (start), startData);

    gtk_widget_show_all (window);
    gtk_main ();

    return 0;

}