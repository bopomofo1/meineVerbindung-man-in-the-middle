#include <gtk/gtk.h>
#include <libnet.h>
#include <pthread.h>
#include "../../modularity/include/error.h"
#include "../../modularity/include/ec_malloc.h"
#include "../../modularity/include/data_pass.h"
#include "../../modularity/include/init.h"
#include "../../arp/include/arp.h"
#include "../../forwarding/include/send_tcp.h"



/*
* Sends text in textentry 1 to target 1
*/

    void
send1(GtkWidget *widget, gpointer data);

    void
send2(GtkWidget *widget, gpointer data);