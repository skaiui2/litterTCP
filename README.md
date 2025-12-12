# litterTCP
这里是教程分支，也就是study分支，主要存放教程对应的项目文件。



## 接口

### tapif文件夹

实现了tapif接口，可以往网卡里写数据并抓包验证，开发环境为ubuntu。

### ethport

这是在stm32f103c8t6最小系统板 + enc28j60模块上实现的网卡接口，可以与主机互发消息并抓包验证，开发环境为windows，使用hal库开发。

#### 接线

除了基本的vcc和gnd外，接线如下：

ENC28J60　　　　　　MCU(STM32F103C8T6)

CS　　　 <--->　　　　GPIO OUTPUT CS针脚，对应PA4

SCK          <--->　　　　SCK 时钟信号，由频率主机控制, 对应 PA5

MISO　　<--->　　　　主机接收，从机发送，对应 PA6

MOSI　　<--->　　　　主机发送，从机接收，对应 PA7
