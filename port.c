#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#include <errno.h>
#include <linux/if.h>
#include <sys/select.h>
#include <pthread.h>
#include "lib/parse.h"
#include "port.h"
#include "litterTCP.h"

int port_if_init(ifnet_class *self)
{
    struct ifreq ifr;
    int err;
    port_net_init(&self->ipaddr, &self->hwaddr, self->mtu);

    if ((self->fd = open("/dev/net/tun", O_RDWR)) < 0) {
        SYS_ERROR("can't open/dev/net/tun");
        return self->fd;
    }
    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

    strncpy(ifr.ifr_name, "tap0", IFNAMSIZ);

    if ((err = ioctl(self->fd, TUNSETIFF, (void *)&ifr)) < 0) {
        SYS_ERROR("ioctl(TUNSETIFF)");
        close(self->fd);
        return err;
    }

    return self->fd;
}

struct buf *port_if_input(ifnet_class *self)
{
    char buf[MLEN];
    struct buf *sk;
    int readlen = read(self->fd, buf, MLEN);
    if (readlen < 0) return NULL;

    sk = buf_get(readlen);
    if (sk == NULL) return NULL;

    memcpy(sk->data, (void *)buf, readlen);
    return sk;
}


int port_if_output(ifnet_class *self, struct buf *sk, uint16_t len)
{
  ssize_t written = write(self->fd, sk->data, len);
  if (written < 0) {
    return written;
  }
  return true;
}


ifnet_class *new_ifnet_class(char *ip, char *mac, unsigned short mtu)
{
    unsigned int addr;
    inet_pton(AF_INET, ip, &addr);

    ifnet_class *net = malloc(sizeof(ifnet_class));
    *net = (ifnet_class) {
        .ipaddr = addr,
        .mtu = mtu,
        .init = port_if_init,
        .input = port_if_input,
        .output = port_if_output
    };

    parse_mac_address(mac, net->hwaddr); 
    return net;
}
