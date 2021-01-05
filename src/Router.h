#ifndef _BOBLI_ROUTER_H
#define _BOBLI_ROUTER_H
#include "Framer.h"
//#include <mutex>
#include <pcap.h>

#pragma comment(lib,"wpcap.lib")

#define _BOBLI_ROUTER_H_TABLE_LEN 32           // 路由表长度
#define _BOBLI_ROUTER_H_MACTABLE_LEN 128       // MAC映射表长度
#define _BOBLI_ROUTER_H_LOG_LEN 512            // 日志记录长度
#define _BOBLI_ROUTER_H_MAX_BIND_IP 10         // 绑定的IP

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
	int valid;						// 标识位，0为无效，1为有效，2为保留项
	int maskLen;					// 掩码长度
	struct Router_Record record;	// 记录项
};

class Router{
public:
	struct IP_MAC_Record macTable[_BOBLI_ROUTER_H_MACTABLE_LEN];	// MAC和IP映射表
	struct MyRouter_Record table[_BOBLI_ROUTER_H_TABLE_LEN];		// 路由表
	IPAddr_t bindIPs[_BOBLI_ROUTER_H_MAX_BIND_IP];                  // 绑定的IP
	MACAddr_t MAC;                                                  // MAC地址
	DWORD workThreadID;												// 路由工作者线程ID
	HANDLE workHandle;												// 路由工作者线程handle
	WorkStatus workStatus;											// 工作状态
	pcap_t* handle;													// 工作的handle
	FILE* logfp;                                                    // logfile指针
	//std::mutex mtx;                                                 // logfile互斥锁
public:
	int find();                                                                 // 寻找下一个空闲的路由表位置
	static DWORD WINAPI workThread(LPVOID lpParam);								// 工作者线程
	static void capNext(Router *);												// 捕获下一个数据报并处理
	static void matchTable(Router *, struct pcap_pkthdr*,const u_char*);		// 根据路由表进行选择
	static int match(MyRouter_Record *, IPAddr_t);								// 若IP与表项匹配，返回掩码长度，否则返回-1
	static void dealARP(Router*, struct pcap_pkthdr*, const u_char*);			// 处理ARP数据报
	static void forward(Router*, struct pcap_pkthdr*, const u_char*, IPAddr_t);	// 转发数据报
	static IPAddr_t getRouterIP(Router*, IPAddr_t);                             // 根据IP地址返回路由器IP
	static int getMAC(MACAddr_t *, Router*, IPAddr_t);							// 根据IP地址获取MAC地址
	static void sendARP(pcap_t*, MACAddr_t*, IPAddr_t, IPAddr_t);				// 发送ARP[pcap_t指针][源MAC][源IP][目的IP]
	static void sendICMP(Router*, pcap_pkthdr*, const u_char *);                // 发送ICMP报文
	static void clearMacTable(Router*);											// 清理MAC表
	static void clearRecord(Router*);							                // 清理路由表
	static void ARPlog(Router*, struct pcap_pkthdr*, const u_char*);            // ARP日志记录
	static void IPlog(Router*, const u_char*, u_char*, IPAddr_t);               // IP日志记录
	static void writelog(Router*, char*, int);                                  // 记录日志
public:
	Router(pcap_t *);
	~Router();
	void bind(IPAddr_t);                        // 绑定IP
	void start();								// 路由器开始工作
	void stop();								// 路由器暂停工作
	int addRecord(struct Router_Record *, int);	// 路由表记录的插入，return -1插入失败，否则返回插入位置
	int delRecord(int);							// 路由表记录的删除，参数为第n个有效记录
	int addMac(MACAddr_t*, IPAddr_t, int);      // MAC表记录的插入
	int delMac(int);                            // MAC表记录的删除
	void printInfo(FILE *);                     // 打印路由器基本信息
	void printRouter(FILE *);					// 向文件流中输出路由表
	void printMAC(FILE *);						// 向文件流中输出MAC表
	void printLog(FILE *);                      // 向文件流中输出日志记录
};

#endif