#include<stdio.h>
#include<pcap.h>
#include<string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/_endian.h>
#include<pthread.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdlib.h>
#include "Header.h"

//#define PACP_ERRBUF_SIZE 256

void callback(u_char * userarg, const struct pcap_pkthdr * pkthdr, const u_char * packet) {
    pcap_dump(userarg, pkthdr, packet);
    printf("--------------------------------------\n");
    struct MacHeader *macHeader = (struct MacHeader*)packet;
    printf("%d %d\n",pkthdr->caplen,pkthdr->len);
    pthread_t t = pthread_self();
    printf("child thread tid = %ld\n", t->__sig);
    printf("分析数据链路层\n");
    printf("目的 Mac地址: %02x:%02x:%02x:%02x:%02x:%02x\n",macHeader->des[0]&0x0ff,macHeader->des[1]&0x0ff,macHeader->des[2]&0x0ff,macHeader->des[3]&0x0ff,macHeader->des[4]&0x0ff,macHeader->des[5]&0x0ff);
    printf("源 Mac地址: %02x:%02x:%02x:%02x:%02x:%02x\n",macHeader->source[0]&0x0ff,macHeader->source[1]&0x0ff,macHeader->source[2]&0x0ff,macHeader->source[3]&0x0ff,macHeader->source[4]&0x0ff,macHeader->source[5]&0x0ff);

    printf("%04x",ntohs(macHeader->type));
    printf("\n");
    printf("分析网络层\n");
    struct IpPackage ipPackage = *((struct IpPackage*)(packet+14));
    struct in_addr sourceIp = {ipPackage.source};
    struct in_addr desIp = {ipPackage.des};
    int *proctoal = (int *)&ipPackage.protocal;
    int *verandlen = (int *)&ipPackage.verandlen;
    printf("协议字段值为%d\n",*proctoal&0xff);
    printf("首部长度为%dB\n",((*verandlen)&0xf)*4);
    printf("数据部分长度为%dB\n",ntohs(ipPackage.packageLen) - ((*verandlen)&0xf)*4);
    printf("片偏移为:%d\n",ntohs(ipPackage.offset&0x1fff));
//    printf("源ip为： ip=%s\n",inet_ntoa(sourceIp));
//    printf("目的ip为： ip=%s\n",inet_ntoa(desIp));
    printf("\n");
    printf("分析运输层\n");
    
    if ((*proctoal&0xff) == 6) {
        printf("tcp包\n");
        struct TcpPackage *tcpPackage = (struct TcpPackage*)(packet+14+((*verandlen)&0xf)*4);
        printf("源端口为%d    ",ntohs(tcpPackage->source));
        printf("目的端口为%d   ",ntohs(tcpPackage->des));
        printf("时间为%ld    ",pkthdr->ts.tv_sec);
        printf("源ip为：ip=%s         ",inet_ntoa(sourceIp));
        printf("目的ip为：ip=%s        ",inet_ntoa(desIp));
        unsigned syn = ntohl(tcpPackage->number);
        printf("序号为%u     ",syn);
        printf("确认号为%u     ",ntohl(tcpPackage->confirmNumber));
        printf("窗口大小为%d    ",ntohs(tcpPackage->windowSize));
        printf("FIN=%d     ",(tcpPackage->others&0x0100) != 0);
        printf("ACK=%d     ",(tcpPackage->others&0x1000) != 0);
        printf("SYN=%d     ",(tcpPackage->others&0x0200) != 0);
        printf("数据部分长度%d         ",ntohs(ipPackage.packageLen) - ((*verandlen)&0xf)*4-((tcpPackage->others&0x00f0)>>4)*4);
        printf("首部长度%d\n",((tcpPackage->others&0x00f0)>>4)*4);
    } else if((*proctoal&0xff) == 17) {
        printf("udp包");
        struct UdpPackage *udpPackage = (struct UdpPackage*)(packet+14+((*verandlen)&0xf)*4);
        printf("源ip为：ip=%s         ",inet_ntoa(sourceIp));
        printf("目的ip为：ip=%s        ",inet_ntoa(desIp));
        printf("源端口为%d    ",htons(udpPackage->source));
        printf("目的端口为%d   ",htons(udpPackage->des));
        printf("数据部分长度%d\n   ",htons(udpPackage->udpLength)-8);
        
    } else {
        printf("其他的 ip包");
    }
 
    printf("++++++++++++++++++++++++++++++++++++++++\n");
}

struct in_addr getIp() {
    static struct in_addr addr = {0};
    if (addr.s_addr == 0) {
        char hname[128];
        struct hostent *hent;
        gethostname(hname, sizeof(hname));
        hent = gethostbyname(hname);
        addr = *(struct in_addr*)(hent->h_addr_list[0]);
    }
    return addr;
}

int getSerive(int port) {
    int i;
    switch (port) {
        case 21:
            i = 0;
            break;
        case 23:
            i = 1;
            break;
        case 25:
            i = 2;
            break;
        case 80:
            i = 3;
            break;
        case 443:
            i = 4;
            break;
        case 53:
            i = 0;
            break;
        case 69:
            i = 1;
            break;
        case 161:
            i = 2;
            break;
        case 67:
            i=3;
            break;
        default:
            i = -1;
            break;
    }
    return i;
}


void saveDataPackage(struct DataPackageQueue*queue,struct DataPackae* dataPackage) {
    struct in_addr addr = getIp();
    ushort port;
    int flag;
    struct DataPackae* temp = NULL;
    struct DataPackae* head = NULL;
    flag = dataPackage->sourceIp.s_addr == addr.s_addr ? 1:0;
    port = flag == 1 ? dataPackage->desPort:dataPackage->sourcePort;
    unsigned int ip = flag == 1 ? dataPackage->desIp.s_addr:dataPackage->sourceIp.s_addr;
 //   printf("源 ip = %s  源端口为 %d  flag = %d port = %d  %d\n",inet_ntoa(dataPackage->sourceIp),dataPackage->sourcePort,flag,port,dataPackage->dataLength);
 //   printf("目的 ip = %s 目的端口为%d\n",inet_ntoa(dataPackage->desIp),dataPackage->desPort);
    int i = getSerive(port);
    if (i == -1) {
        printf("未知应用层服务  port = %d\n",port);
        free(dataPackage);
        return;
    }
    int j = (dataPackage->sourceIp.s_addr ^ dataPackage->desIp.s_addr) % 256;
    if (flag == 1) {
        queue[i].uploadCount += dataPackage->dataLength;
        queue[i].uploadDuringCount += dataPackage->dataLength;
        queue[i].package[j].uploadCount += dataPackage->dataLength;
        head = (queue[i].package[j].upload);
        if (queue[i].package[j].upload == NULL) {
            queue[i].package[j].upload = dataPackage;
            return;
        }
    } else if(flag == 0) {
        queue[i].downCount += dataPackage->dataLength;
        queue[i].downDuringCount += dataPackage->dataLength;
        queue[i].package[j].downCount += dataPackage->dataLength;
        head = (queue[i].package[j].down);
        if (queue[i].package[j].down == NULL) {
            queue[i].package[j].down = dataPackage;
            return;
        }
    }

    temp = head;
    unsigned int findIp = flag == 1 ? dataPackage->desIp.s_addr:dataPackage->sourceIp.s_addr;
    while (temp) {
        if (findIp == ip) {
            dataPackage->next = temp->next;
            temp->next = dataPackage;
            break;
        }
        if (temp->next == NULL) {
            temp->next = dataPackage;
            break;
        }
        temp = temp->next;
    }
    
}


void freeDataPackae(struct DataPackae* dataPackage) {
    struct DataPackae* temp;
    printf("开始释放\n");
    while(dataPackage) {
        temp = dataPackage;
        printf("源ip为%s       目的ip为%s     ", inet_ntoa(dataPackage->sourceIp),inet_ntoa(dataPackage->desIp));
        printf("目的端口为%d    源端口%d     ",dataPackage->sourcePort,dataPackage->desPort);
        printf("ip头部长度%d    运输层头部长度%d     数据部分长度%d\n",dataPackage->ipHeaderLength,dataPackage->headerLength,dataPackage->dataLength);
        dataPackage = dataPackage->next;
        free(temp);
    }
    printf("结束释放\n");
}

void freeQueue() {
     for (int i = 0; i < 5; i++) {
        printf("应用层协议:%s   总的上传量%ld   总的下载量%ld   一个时间片内上传量%ld    一个时间片内下载量%ld\n",tcpName[i]
               ,tcpQueue[i].uploadCount,tcpQueue[i].downCount,tcpQueue[i].uploadDuringCount,
               tcpQueue[i].downDuringCount);
        tcpQueue[i].downDuringCount = 0;
        tcpQueue[i].uploadDuringCount = 0;
        if (tcpQueue[i].downDuringCount == 0 && tcpQueue[i].uploadDuringCount == 0) {
            continue;
        }

        for (int j = 0; j < 256; j++) {
            struct Package tcp = tcpQueue[i].package[j];
            if (tcp.downCount != 0) {
                freeDataPackae(tcp.down);
                tcp.downCount = 0;
            }
            tcp.down = NULL;
            if (tcp.uploadCount !=0) {
                freeDataPackae(tcp.upload);
                tcp.uploadCount = 0;
            }
            tcp.upload = NULL;
            
        }
    }
    
    for (int i = 0; i < 5; i++) {
        printf("应用层协议:%s   总的上传量%ld   总的下载量%ld   一个时间片内上传量%ld    一个时间片内下载量%ld\n",utpName[i]
               ,udpQueue[i].uploadCount,udpQueue[i].downCount,udpQueue[i].uploadDuringCount,
               udpQueue[i].downDuringCount);
        udpQueue[i].downDuringCount = 0;
        udpQueue[i].uploadDuringCount = 0;
        if (udpQueue[i].downDuringCount == 0 && udpQueue[i].uploadDuringCount == 0) {
            continue;
        }
        for (int j = 0; j < 256; j++) {
            struct Package udp = udpQueue[i].package[j];
            if (udp.downCount != 0) {
                freeDataPackae(udp.down);
                udp.downCount = 0;
            }
            udp.down = NULL;
            if (udp.uploadCount != 0) {
                freeDataPackae(udp.upload);
                udp.uploadCount = 0;
                
            }
            udp.upload = NULL;
        }
    }
}

void analysisCallback(u_char * userarg, const struct pcap_pkthdr * pkthdr, const u_char * packet) {
    static long seconds = -1;
    static int during = 60;
    if (seconds == -1) {
        seconds = pkthdr->ts.tv_sec;
        during = atoi((char*)userarg);
    }
    if((pkthdr->ts.tv_sec - seconds) >= during) {
        printf("%ld 到 %ld\n",seconds,pkthdr->ts.tv_sec);
        seconds = pkthdr->ts.tv_sec;
        freeQueue();
    }
    
    //struct MacHeader *macHeader = (struct MacHeader*)packet;
    struct IpPackage ipPackage = *((struct IpPackage*)(packet+14));
    int *proctoal = (int *)&ipPackage.protocal;
    struct DataPackae* dataPackage = NULL;
    dataPackage = (struct DataPackae*)malloc(sizeof(struct DataPackae));
    memset(dataPackage, 0, sizeof(struct DataPackae));
    if(dataPackage == NULL) {
        printf("error");
        exit(0);
    }
    struct in_addr sourceIp = {ipPackage.source};
    struct in_addr desIp = {ipPackage.des};

    dataPackage->desIp.s_addr = desIp.s_addr;
    dataPackage->sourceIp.s_addr = sourceIp.s_addr;
    
    int *verandlen = (int *)&ipPackage.verandlen;
    dataPackage->ipHeaderLength = ((*verandlen)&0xf)*4;
    dataPackage->ts = pkthdr->ts;
    dataPackage->next = NULL;
    if ((*proctoal&0xff) == 6) {
        struct TcpPackage *tcpPackage = (struct TcpPackage*)(packet+14+((*verandlen)&0xf)*4);
        dataPackage->desPort = htons(tcpPackage->des);
        dataPackage->sourcePort = htons(tcpPackage->source);
        dataPackage->headerLength = ((tcpPackage->others&0x00f0)>>4)*4;
        dataPackage->dataLength = htons(ipPackage.packageLen) - ((*verandlen)&0xf)*4-((tcpPackage->others&0x00f0)>>4)*4;
        if (dataPackage->dataLength == 0) {
            free(dataPackage);
        }else {
           saveDataPackage(tcpQueue,dataPackage);
        }
    } else if ((*proctoal&0xff) == 17) {
        struct UdpPackage *udpPackage = (struct UdpPackage*)(packet+14+((*verandlen)&0xf)*4);
        dataPackage->desPort = htons(udpPackage->des);
        dataPackage->sourcePort = htons(udpPackage->source);
        dataPackage->headerLength = 8;
        dataPackage->dataLength = htons(udpPackage->udpLength)-8;
        if (dataPackage->dataLength == 0) {
            free(dataPackage);
        }else {
            saveDataPackage(udpQueue,dataPackage);
        }
    } else {
        printf("其他协议字段%d\n",*proctoal&0xff);
        free(dataPackage);
    }
}




int main(int argc,char*argv[])
{
    
 
    
    
    
    
    int flag = atoi(argv[1]);
    if (flag == 1) {
        char *device;//用来保存打开的设备
        char errBuf[PCAP_ERRBUF_SIZE];//保存错误信息
        device = pcap_lookupdev(errBuf);
        if (device == NULL ) {
            perror("no have net device");
            return 0;
        }
        printf("%s",device);
        bpf_u_int32 ip;
        bpf_u_int32 ma;
        pcap_lookupnet(device, &ip, &ma, errBuf);
        struct in_addr sin_addrIP;
        sin_addrIP.s_addr = ip;
        struct in_addr sin_addrMa = {ma};
        printf("本机的网络号： ip=%s\n",inet_ntoa(sin_addrIP));
        printf("本机子网掩码为： ma=%s\n",inet_ntoa(sin_addrMa));
        
        pcap_t *p = pcap_open_live(device, 65535, 0, 0, errBuf);
        int dataType = pcap_datalink(p);
        if (dataType != DLT_EN10MB) {
            printf("本程序只支持Ethernet的数据链路标准，其他标准请自行修改从链路层得到ip数据报的代码\n");
            return 0;
        }
        if (p == NULL) {
            printf("error11\n");
            return 0;
        }
        printf("开始监听\n");
        pcap_dumper_t *k = pcap_dump_open(p, "./test.pcap");
        if (k == NULL) {
            printf("%s",pcap_geterr(p));
        }
        struct bpf_program filter;
        pcap_compile(p, &filter, argv[2], 1, ma);
        pcap_setfilter(p, &filter);
        pcap_loop(p, -1, callback, (u_char*)k);
        pcap_close(p);
    } else if(flag == 2){
        char errBuf[PCAP_ERRBUF_SIZE];//保存错误信息
        pcap_t*p = pcap_open_offline(argv[2], errBuf);
        if (p == NULL) {
            printf("error\n");
            return 0;
        }
        int dataType = pcap_datalink(p);
        if (dataType != DLT_EN10MB) {
            printf("本程序只支持Ethernet的数据链路标准，其他标准请自行修改从链路层得到ip数据报的代码\n");
            return 0;
        }
        pcap_loop(p, -1, analysisCallback, (u_char*)argv[3]);
        pcap_close(p);
    }
    
    
    

}












