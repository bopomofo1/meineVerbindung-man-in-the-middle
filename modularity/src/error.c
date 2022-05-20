// Contains function to handle errors

#include "../include/error.h"


// A function to display an error message with origin (Where is it) and then exit
    void 
fatal(char *message, char *origin) 
{
    char error_message[100];
    strcpy(error_message, "[!!] Fatal Error ");
    strncat(error_message, message, 83);
    perror(error_message);
    perror(origin);
    exit(EXIT_FAILURE);
}