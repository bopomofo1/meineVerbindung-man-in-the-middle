// Structs to pass data to another thread

#pragma once

#include <libnet.h>

struct data_pass {
    uint8_t *mac1;
    uint8_t *mac2;
    uint32_t ip1;
    uint32_t ip2;
    libnet_t *l;
};
