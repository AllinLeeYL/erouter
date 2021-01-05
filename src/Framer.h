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
// ��̫������֡�ײ�
typedef struct {
	MACAddr_t DesMAC;		//Ŀ��MAC��ַ
	MACAddr_t SrcMAC;		//ԴMAC��ַ
	uint16_t FrameType;		//����֡����
} EthernetHeader_t;
// IP���ݱ��ײ�
typedef struct {
	uint8_t Ver_HLen;		//�汾��[0:3]���ײ�����[4:7]
	uint8_t TOS;			//��������
	uint16_t TotalLen;		//�ܳ���
	uint16_t ID;			//��ʶ
	uint16_t Flag_segment;	//��־[0:2]��Ƭƫ��[3:15]
	uint8_t TTL;			//��������
	uint8_t Protocol;		//������Э������
	uint16_t Checksum;		//У���
	IPAddr_t SrcIP;			//ԴIP
	IPAddr_t DesIP;			//Ŀ��IP
} IPHeader_t;
// ARP���ݱ��ײ�
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
// ICMP���ݱ�
typedef struct {
	uint8_t Type;
	uint8_t Code;
	uint16_t Checksum;
	uint32_t Options;
} ICMPHeader_t;
// ARP���ݱ�
struct ARPFrame {
	EthernetHeader_t Eth_header;
	ARPHeader_t ARP_header;
};
// IP���ݱ�
struct IPFrame {
	EthernetHeader_t Eth_header;
	IPHeader_t IP_header;
};
#pragma pack()

int bitCount(uint32_t);
void bstrcpy(u_char* __des__, const u_char* __src__, int __length__);
void copyMAC(MACAddr_t *, MACAddr_t *);
int checkIP(struct IPFrame *);

/*����IP���ݱ���У��ͣ����������򣨴�ˣ���16bitУ���*/
uint16_t computeCheckSum(u_char *, int);

/*����ʾIP��stringת����u_char[4]��IP����
Ҳ���Ǵ��ģʽ�������򣩱�ʾ��32λIP��ַ*/
void Convert_string_to_IP(u_char* __IP__, char* __string__);
#endif