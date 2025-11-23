#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#include <errno.h>
#include <linux/if.h>
#include <sys/select.h>
#include <pthread.h>
#include <arpa/inet.h>
#include "parse.h"
#include "port.h"
#include "buf.h"
#include "heap.h"

//Private data, like this:
Class(net_private) {
    unsigned int output_count;
    unsigned int input_count;
    unsigned int data_len_input_count;
    unsigned int data_len_output_count;
};

ifnet_class *self = NULL;


pthread_mutex_t net_input_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t net_output_lock = PTHREAD_MUTEX_INITIALIZER;
net_private net_pri = (net_private) {
    .data_len_input_count = 0,
    .data_len_output_count = 0,
    .input_count = 0,
    .output_count = 0
};


int port_if_init(char *ip, char *mac, unsigned short mtu)
{
    struct ifreq ifr;
    int err = -1;

    if ((self->fd = open("/dev/net/tun", O_RDWR)) < 0) {
        return err;
    }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

    strncpy(ifr.ifr_name, "tap0", IFNAMSIZ);

    if ((err = ioctl(self->fd, TUNSETIFF, (void *)&ifr)) < 0) {
        close(self->fd);
        return err;
    }

    self->private = &net_pri;

    inet_pton(AF_INET, ip, &self->ipaddr);
    self->mtu = mtu;
    parse_mac_address(mac, self->hwaddr);

    return 0;
}

struct buf *port_if_input()
{
    pthread_mutex_lock(&net_input_lock);

    char buf[MLEN];
    struct buf *sk;
    int readlen = read(self->fd, buf, MLEN);
    if (readlen < 0) return NULL;

    sk = buf_get(readlen);
    if (sk == NULL) return NULL;

    memcpy(sk->data, (void *)buf, readlen);

    net_pri.input_count++;
    net_pri.data_len_input_count += readlen;

    pthread_mutex_unlock(&net_input_lock);
    return sk;
}


int port_if_output(struct buf *sk)
{
    pthread_mutex_lock(&net_output_lock);
    
    int written = write(self->fd, sk->data, sk->data_len);
    if (written < 0) {
        return written;
    }

    net_pri.output_count++;
    net_pri.data_len_output_count += written;
    
    pthread_mutex_unlock(&net_output_lock);
    return 0;
}

ifnet_class *new_ifnet_class()
{
    self = heap_malloc(sizeof(ifnet_class));
    *self = (ifnet_class) {
        .init = port_if_init,
        .input = port_if_input,
        .output = port_if_output
    };

    return self;
}
