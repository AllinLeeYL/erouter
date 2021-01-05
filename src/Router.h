#ifndef _BOBLI_ROUTER_H
#define _BOBLI_ROUTER_H
#include "Framer.h"
//#include <mutex>
#include <pcap.h>

#pragma comment(lib,"wpcap.lib")

#define _BOBLI_ROUTER_H_TABLE_LEN 32           // ·�ɱ���
#define _BOBLI_ROUTER_H_MACTABLE_LEN 128       // MACӳ�����
#define _BOBLI_ROUTER_H_LOG_LEN 512            // ��־��¼����
#define _BOBLI_ROUTER_H_MAX_BIND_IP 10         // �󶨵�IP

enum WorkStatus {
	WorkStatus_Active = 1,
	WorkStatus_Stop = 2,
	WorkStatus_Close = 3
};

struct IP_MAC_Record {
	MACAddr_t MAC;
	IPAddr_t IP;
	int valid;
};

struct Router_Record{
	IPAddr_t DesIP;
	IPAddr_t NetMask;
	IPAddr_t NextHop;
};

struct MyRouter_Record {
	int valid;						// ��ʶλ��0Ϊ��Ч��1Ϊ��Ч��2Ϊ������
	int maskLen;					// ���볤��
	struct Router_Record record;	// ��¼��
};

class Router{
public:
	struct IP_MAC_Record macTable[_BOBLI_ROUTER_H_MACTABLE_LEN];	// MAC��IPӳ���
	struct MyRouter_Record table[_BOBLI_ROUTER_H_TABLE_LEN];		// ·�ɱ�
	IPAddr_t bindIPs[_BOBLI_ROUTER_H_MAX_BIND_IP];                  // �󶨵�IP
	MACAddr_t MAC;                                                  // MAC��ַ
	DWORD workThreadID;												// ·�ɹ������߳�ID
	HANDLE workHandle;												// ·�ɹ������߳�handle
	WorkStatus workStatus;											// ����״̬
	pcap_t* handle;													// ������handle
	FILE* logfp;                                                    // logfileָ��
	//std::mutex mtx;                                                 // logfile������
public:
	int find();                                                                 // Ѱ����һ�����е�·�ɱ�λ��
	static DWORD WINAPI workThread(LPVOID lpParam);								// �������߳�
	static void capNext(Router *);												// ������һ�����ݱ�������
	static void matchTable(Router *, struct pcap_pkthdr*,const u_char*);		// ����·�ɱ����ѡ��
	static int match(MyRouter_Record *, IPAddr_t);								// ��IP�����ƥ�䣬�������볤�ȣ����򷵻�-1
	static void dealARP(Router*, struct pcap_pkthdr*, const u_char*);			// ����ARP���ݱ�
	static void forward(Router*, struct pcap_pkthdr*, const u_char*, IPAddr_t);	// ת�����ݱ�
	static IPAddr_t getRouterIP(Router*, IPAddr_t);                             // ����IP��ַ����·����IP
	static int getMAC(MACAddr_t *, Router*, IPAddr_t);							// ����IP��ַ��ȡMAC��ַ
	static void sendARP(pcap_t*, MACAddr_t*, IPAddr_t, IPAddr_t);				// ����ARP[pcap_tָ��][ԴMAC][ԴIP][Ŀ��IP]
	static void sendICMP(Router*, pcap_pkthdr*, const u_char *);                // ����ICMP����
	static void clearMacTable(Router*);											// ����MAC��
	static void clearRecord(Router*);							                // ����·�ɱ�
	static void ARPlog(Router*, struct pcap_pkthdr*, const u_char*);            // ARP��־��¼
	static void IPlog(Router*, const u_char*, u_char*, IPAddr_t);               // IP��־��¼
	static void writelog(Router*, char*, int);                                  // ��¼��־
public:
	Router(pcap_t *);
	~Router();
	void bind(IPAddr_t);                        // ��IP
	void start();								// ·������ʼ����
	void stop();								// ·������ͣ����
	int addRecord(struct Router_Record *, int);	// ·�ɱ��¼�Ĳ��룬return -1����ʧ�ܣ����򷵻ز���λ��
	int delRecord(int);							// ·�ɱ��¼��ɾ��������Ϊ��n����Ч��¼
	int addMac(MACAddr_t*, IPAddr_t, int);      // MAC���¼�Ĳ���
	int delMac(int);                            // MAC���¼��ɾ��
	void printInfo(FILE *);                     // ��ӡ·����������Ϣ
	void printRouter(FILE *);					// ���ļ��������·�ɱ�
	void printMAC(FILE *);						// ���ļ��������MAC��
	void printLog(FILE *);                      // ���ļ����������־��¼
};

#endif