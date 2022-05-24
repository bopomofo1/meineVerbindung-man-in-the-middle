#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>
#include <gtk/gtk.h>
#include "../../modularity/include/ec_malloc.h"

    int
display_data(u_char *packet, uint size, GtkTextView *chat);