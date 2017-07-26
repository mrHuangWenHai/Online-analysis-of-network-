//
//  Header.h
//  net
//
//  Created by 黄文海 on 2017/7/4.
//  Copyright © 2017年 huang. All rights reserved.
//

#ifndef Header_h
#define Header_h
struct MacHeader {
    char des[6];
    char source[6];
    short type;
};

struct IpPackage{
    char verandlen;
    char server;
    ushort packageLen;
    ushort tag;
    ushort offset;
    char time;
    char protocal;
    ushort check;
    unsigned source;
    unsigned des;
};

struct TcpPackage{
    ushort source;
    ushort des;
    unsigned number;
    unsigned confirmNumber;
    ushort others;
    ushort windowSize;
    ushort check;
    ushort urgentPoniter;
};

struct UdpPackage{
    ushort source;
    ushort des;
    ushort udpLength;
    short check;
};

struct DataPackae {
    struct in_addr sourceIp;
    struct in_addr desIp;
    ushort ipHeaderLength;
    int sourcePort;
    ushort desPort;
    ushort headerLength;
    ushort dataLength;
    struct timeval ts;
    struct DataPackae*next;
};

struct Package {
    struct DataPackae* down;
    struct DataPackae* upload;
    long downCount;
    long uploadCount;
};

struct DataPackageQueue{
    struct Package package[256];
    long downDuringCount;
    long uploadDuringCount;
    long downCount;
    long uploadCount;
};
struct DataPackageQueue tcpQueue[5];
struct DataPackageQueue udpQueue[5];

char tcpName[5][10] = {{"FTP"},{"TELNET"},{"SMTP"},{"HTTP"},{"HTPPS"}};
char utpName[5][10] = {{"DNS"},{"TFTP"},{"SNMP"},{"DHCP"},{"RIP"}};

#endif /* Header_h */
