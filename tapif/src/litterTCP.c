#include "litterTCP.h"
#include "buf.h"
#include "port.h"
#include "heap.h"


void test() 
{
    auto_free ifnet_class *net1 = new_ifnet_class();
    net1->init("192.168.1.200", "9e:4d:9e:e3:48:9f", 1460);
    
    char arp_request[42] = {
        // 以太网头
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,       // 目标 MAC：广播
        0x00, 0x0c, 0x29, 0xab, 0xcd, 0xef,       // 源 MAC：自定义
        0x08, 0x06,                               // 类型：ARP (0x0806)

        // ARP Header
        0x00, 0x01,                               // 硬件类型：以太网
        0x08, 0x00,                               // 协议类型：IPv4
        0x06,                                     // MAC 长度
        0x04,                                     // IP 长度
        0x00, 0x01,                               // 操作码：请求

        // Sender MAC
        0x00, 0x0c, 0x29, 0xab, 0xcd, 0xef,
        // Sender IP
        0xc0, 0xa8, 0x01, 0x02,                   // 192.168.1.2

        // Target MAC（未知）
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // Target IP
        0xc0, 0xa8, 0x5b, 0x82   // 192.168.91.130
    };
    auto_sk_free struct buf *sk = buf_get(sizeof(arp_request));
    memcpy(sk->data, arp_request, sizeof(arp_request));

    net1->output(sk);
}


extern unsigned int alloc_count;
extern unsigned int free_count;
int main()
{
    test();
    printf("alloc_count: %u\n", alloc_count);
    printf("free_count: %u\n", free_count);
}


