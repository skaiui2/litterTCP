#ifndef PARSE_H
#define PARSE_H
#include <string.h>
#include <stdlib.h>

static inline void parse_mac_address(const char *mac, unsigned char hwaddr[6]) 
{
    char mac_copy[18]; 
    strncpy(mac_copy, mac, sizeof(mac_copy) - 1);
    mac_copy[sizeof(mac_copy) - 1] = '\0'; 

    char *token = strtok(mac_copy, ":"); 
    for (int i = 0; i < 6 && token != NULL; i++) {
        hwaddr[i] = (unsigned char)strtol(token, NULL, 16);
        token = strtok(NULL, ":");
    }
}



#endif