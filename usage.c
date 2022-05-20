#include "usage.h"

// Prints how to use the program  
void usage(char* name)
{
    printf("Usage: %s <IP of Target A> <IP of Target B>\n", name);
    exit(0);
}