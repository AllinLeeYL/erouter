#ifndef _BOBLI_FRAMER_H
#define _BOBLI_FRAMER_H
#include <stdlib.h>
#include <stdint.h>
#include <WinSock2.h>
#include <Windows.h>

#pragma comment(lib,"ws2_32.lib")

#pragma pack(1)
typedef struct {
	uint8_t MAC[6];
} MACAddr_t;
typedef uint32_t IPAddr_t;
// 以太网数据帧首部
typedef struct {
	MACAddr_t DesMAC;		//目的MAC地址
	MACAddr_t SrcMAC;		//源MAC地址
	uint16_t FrameType;		//数据帧类型
} EthernetHeader_t;
// IP数据报首部
typedef struct {
	uint8_t Ver_HLen;		//版本号[0:3]，首部长度[4:7]
	uint8_t TOS;			//服务类型
	uint16_t TotalLen;		//总长度
	uint16_t ID;			//标识
	uint16_t Flag_segment;	//标志[0:2]和片偏移[3:15]
	uint8_t TTL;			//生存周期
	uint8_t Protocol;		//数据区协议类型
	uint16_t Checksum;		//校验和
	IPAddr_t SrcIP;			//源IP
	IPAddr_t DesIP;			//目的IP
} IPHeader_t;
// ARP数据报首部
typedef struct {
	uint16_t HardwareType;
	uint16_t ProtocolType;
	uint8_t HardwareLen;
	uint8_t ProtocolLen;
	uint16_t Operation;
	MACAddr_t SrcHardwareMAC;
	IPAddr_t SrcIP;
	MACAddr_t DesHardwareMAC;
	IPAddr_t DesIP;
} ARPHeader_t;
// ICMP数据报
typedef struct {
	uint8_t Type;
	uint8_t Code;
	uint16_t Checksum;
	uint32_t Options;
} ICMPHeader_t;
// ARP数据报
struct ARPFrame {
	EthernetHeader_t Eth_header;
	ARPHeader_t ARP_header;
};
// IP数据报
struct IPFrame {
	EthernetHeader_t Eth_header;
	IPHeader_t IP_header;
};
#pragma pack()

int bitCount(uint32_t);
void bstrcpy(u_char* __des__, const u_char* __src__, int __length__);
void copyMAC(MACAddr_t *, MACAddr_t *);
int checkIP(struct IPFrame *);

/*计算IP数据报的校验和，返回网络序（大端）的16bit校验和*/
uint16_t computeCheckSum(u_char *, int);

/*将表示IP的string转换成u_char[4]的IP数组
也就是大端模式（网络序）表示的32位IP地址*/
void Convert_string_to_IP(u_char* __IP__, char* __string__);
#endif