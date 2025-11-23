#ifndef PORT_H
#define PORT_H
#include "lib/class.h"

struct _in_addr {
    unsigned int   addr;
};

struct _sockaddr_in {
	unsigned char	    sin_len;
	unsigned char	    sin_family;
	unsigned short	    sin_port;
	struct	_in_addr   	sin_addr;
	char    	        sin_zero[8];
};


class(ifnet) {
    int fd;         //device fd
    struct ifnet *if_next;
    struct list_node *if_addrlist;
    struct _in_addr ipaddr;
    struct _in_addr netmask;
    struct _in_addr gw;
    unsigned char hwaddr[6];
    unsigned short mtu;
    void *state;

    int  (*init)(ifnet_class *self, char *ip, char *mac, unsigned short mtu);
    struct buf* (*input)(ifnet_class *self);
    int  (*output)(ifnet_class *self, struct buf *sk, uint16_t len);
};

ifnet_class *new_ifnet_class(char *ip, char *mac, unsigned short mtu);


#endif 
