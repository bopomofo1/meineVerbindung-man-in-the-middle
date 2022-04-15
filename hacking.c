#include "header/hacking.h"

// A function to display an error message and then exit
void fatal(char *message) 
{
    char error_message[100];
    strcpy(error_message, "[!!] Fatal Error ");
    strncat(error_message, message, 83);
    perror(error_message);
    exit(-1);
}

// An error-checked malloc() wrapper function
void *ec_malloc(unsigned int size) 
{
    void *ptr;
    ptr = malloc(size);
    if(ptr == NULL)
    fatal("in ec_malloc() on memory allocation");
    return ptr;
}

// Speicherdump mit Hexbytes und druckbaren Zeichen

// Dumps raw memory in ascciia
void dump(const unsigned char *data_buffer, const unsigned int length) {
    unsigned char byte;
    unsigned int i, j;
    printf("\t");
    for(int i = 0; i < length; i++)
    {
        if(i % 20 == 19) 
            printf("\n\t");

        // Is it inside the printable range
        if((data_buffer[i] > 37 && data_buffer[i] < 127) || data_buffer[i] == ' ')
            printf("%c", data_buffer[i]);
        else 
            printf(".");
    }
}
