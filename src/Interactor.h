#ifndef _BOBLI_INTERACTOR_H
#define _BOBLI_INTERACTOR_H
#include "Router.h"
#include <stdio.h>
#include <string.h>

#define _BOBLI_INTERACTOR_H_INPUT_LEN 256
#define _BOBLI_INTERACTOR_H_MAX_IP_NUM 10

class Interactor{
public:
	char input[_BOBLI_INTERACTOR_H_INPUT_LEN];         // �����ַ���
	Router* router;                                    // ·��������
	pcap_t* handle;                                    // pcap_t
	IPAddr_t IPs[_BOBLI_INTERACTOR_H_MAX_IP_NUM];      // �����󶨵�IP
	IPAddr_t NetMasks[_BOBLI_INTERACTOR_H_MAX_IP_NUM]; // IP��Ӧ����������
public:
	pcap_t* selDev();           // ���豸�����豸�󶨵�IP���浽this->IPs�����ظ��豸�򿪵�pcap_t*
	void saveIPs(pcap_if_t*);	// ����������IP��ַ
	void initRouter(Router*);   // ��IP����MAC��ַ
	void printHelp();           // ��ӡ����
	void printHead();           // ͷ��Ϣ
	char* getInput();			// ��ȡ���룬���浽this->input�У�����ָ��this->input��ָ�룬����������򷵻�NULL
	int parseInput(char *);     // ������������дʷ�����
	char** split(int*, char *); // �ָ�������ַ���
public:
	Interactor();
	~Interactor();

	void work();                        // ����ӿڣ������Խ��й���
	int addRecord(int, char **);		// ���ز���ֵ���������ʽ����ȷ������-1
	int delRecord(int, char **);		// ���ز���ֵ���������ʽ����ȷ������-1
	int printSomething(int, char **);	// ���ز���ֵ���������ʽ����ȷ������-1
};

#endif