// Contains a function to compare two unsigned 6 byte arrays

#include "../include/compare_mac.h"


/* 
* Function to compare two mac addresses.
* Returns 1 if they are the same and
* 0 if not
*/

    int
compare_mac(u_int8_t *mac1, u_int8_t *mac2) {
    for (int i = 0; i < 6; i++) {
        if (mac1[i] != mac2[i])
            return 0;
        return 1;
    }
}