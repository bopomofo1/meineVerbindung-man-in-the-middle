#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// A function to display an error message and then exit
void fatal(char *message);

// An error-checked malloc() wrapper function
void *ec_malloc(unsigned int size);

// Speicherdump mit Hexbytes und druckbaren Zeichen

// Dumps raw memory in hex byte and printable split format
void dump(const unsigned char *data_buffer, const unsigned int length);