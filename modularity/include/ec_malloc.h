#include <stdlib.h>
#include "error.h"

// An error-checked malloc() wrapper function
    void *
ec_malloc(unsigned int size);