// Provides an error checked malloc function

#include "../include/ec_malloc.h"

// An error-checked malloc() wrapper function
    void *
ec_malloc(unsigned int size) {
    void *ptr;
    ptr = malloc(size);
    if(ptr == NULL)
        fatal("in ec_malloc() on memory allocation", "ec_malloc.c, line 9");
    return ptr;
}