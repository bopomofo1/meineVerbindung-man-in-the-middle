#include <gtk/gtk.h>
#include <libnet.h>
#include <pthread.h>
#include "../../modularity/include/error.h"
#include "../../modularity/include/ec_malloc.h"
#include "../../modularity/include/data_pass.h"
#include "../../modularity/include/init.h"
#include "../../arp/include/arp.h"

    void
start(GtkWidget *widget, gpointer data);