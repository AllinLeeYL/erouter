#include "Interactor.h"

Interactor::Interactor() {
	memset(this->input, 0, _BOBLI_INTERACTOR_H_INPUT_LEN);
	memset(this->IPs, 0, sizeof(IPAddr_t)*_BOBLI_INTERACTOR_H_MAX_IP_NUM);
	this->router = NULL;
	this->handle = NULL;
	if (this->selDev() != NULL) {
		// 设置过滤器
		struct bpf_program filter;
		pcap_compile(this->handle, &filter, "ip or arp", 1, 0);
		pcap_setfilter(this->handle, &filter);
		this->router = new Router(this->handle);
		// 初始化路由器
		this->initRouter(this->router);
		this->router->printInfo(stdout);
	}
}

Interactor::~Interactor() {
	;
}

void Interactor::work(){
	this->printHelp();
	while (1) {
		this->printHead();
		this->getInput();
		int n = this->parseInput(this->input);
		if (n == -1) {
			return;
		}
		else if (n == 0) {
			this->printHelp();
		}
	}
}

int Interactor::addRecord(int argc, char** argv){
	if (argc != 5) {
		return -1;
	}
	struct Router_Record record;
	Convert_string_to_IP((u_char*)&(record.DesIP), argv[2]);
	Convert_string_to_IP((u_char*)&(record.NetMask), argv[3]);
	Convert_string_to_IP((u_char*)&(record.NextHop), argv[4]);
	record.DesIP = record.DesIP & record.NetMask;
	return this->router->addRecord(&record, 1) == -1 ? 0 : 1;
}

int Interactor::delRecord(int argc, char** argv){
	this->router->delRecord(atoi(argv[2]));
	return 0;
}

int Interactor::printSomething(int argc, char** argv){
	if (argc != 3) {
		return -1;
	}
	if (strcmp(argv[2], "table") == 0) {
		//打印路由表
		this->router->printRouter(stdout);
		return 1;
	}
	else if (strcmp(argv[2], "log") == 0) {
		//打印日志
		this->router->printLog(stdout);
		return 1;
	}
	else if (strcmp(argv[2], "mactable") == 0) {
		//打印MAC-IP映射表
		this->router->printMAC(stdout);
		return 1;
	}
	return -1;
}

pcap_t* Interactor::selDev(){
	pcap_if_t* alldevs,* curdev;
	char errbuf[PCAP_ERRBUF_SIZE];
	// 查找设备
	if (pcap_findalldevs(&alldevs, errbuf) < 0) {
		perror(errbuf);
		exit(1);
	}
	curdev = alldevs;
	// 显示所有设备
	for (int i = 1; curdev != NULL; i = i + 1) {
		printf("No,%d\n", i);
		if (curdev->name != NULL) {
			printf("\tname: %s\n", curdev->name);
		}
		if (curdev->description != NULL) {
			printf("\tdescription: %s\n", curdev->description);
		}
		curdev = curdev->next;
	}
	// 选择设备
	printf("\nPlease select a device: ");
	while (1) {
		int n = atoi(this->getInput());
		curdev = alldevs;
		for (int i = 1; curdev != NULL; i = i + 1) {
			if (n == i) {
				this->handle = pcap_open_live(curdev->name, 65535, 0, 1000, errbuf);
				pcap_setnonblock(this->handle, 1, errbuf);
				// 保存IP
				this->saveIPs(curdev);
				pcap_freealldevs(alldevs);
				return this->handle;
			}
			curdev = curdev->next;
		}
	}
	// 释放资源
	pcap_freealldevs(alldevs);
	return NULL;
}

void Interactor::saveIPs(pcap_if_t * curdev){
	int i = 0;
	for (pcap_addr_t* a = curdev->addresses; a != NULL; a = a->next) {
		if (a->addr->sa_family == AF_INET && a->netmask->sa_family == AF_INET) {
			struct sockaddr_in *tempB = (struct sockaddr_in*)a->addr;
			Convert_string_to_IP((u_char*)(&this->IPs[i]), inet_ntoa(tempB->sin_addr));
			tempB = (struct sockaddr_in*)a->netmask;
			Convert_string_to_IP((u_char*)(&this->NetMasks[i]), inet_ntoa(tempB->sin_addr));
			i = i + 1;
		}
	}
}

void Interactor::initRouter(Router*){
	for (int i = 0; i < _BOBLI_INTERACTOR_H_MAX_IP_NUM && this->IPs[i] != 0; i = i + 1) {
		Router_Record record;
		MACAddr_t MAC;
		record.DesIP = this->IPs[i];
		record.NetMask = this->NetMasks[i];
		record.NextHop = 0;
		this->router->addRecord(&record, 2);
		this->router->bind(this->IPs[i]);
		int n = 0;
		while (1) {
			struct pcap_pkthdr* pcap_header;
			const u_char* pcap_data;
			this->router->sendARP(this->handle, &(this->router->macTable[0].MAC), 20, this->IPs[i]);
			n = pcap_next_ex(this->handle, &pcap_header, &pcap_data);
			if (n <= 0) {
				continue;
			}
			ARPFrame* ARP = (ARPFrame*)pcap_data;
			if (ARP->ARP_header.SrcIP != this->IPs[i]) {
				continue;
			}
			copyMAC(&(this->router->MAC), &(ARP->ARP_header.SrcHardwareMAC));
			this->router->addMac(&(this->router->MAC), this->IPs[i], 2);
			break;
		}
	}
}

void Interactor::printHelp() {
	printf("Usage: router [options] [target] ...\n");
	printf("Options:\n");

	printf("\tadd\t\tAdd a record to router table. ");
	printf("router add [DesIP] [NetMask] [NextHop]\n");

	printf("\tdel\t\tDelete a record to router table. ");
	printf("router del [No]\n");

	printf("\thelp\t\tHelp.\n");

	printf("\tprint\t\tPrint [table] for router table, [mactable] for mac-ip table, [log] for the log file.\n");
	printf("\tquit\t\tClose router and quit this program.\n");
	printf("\tstart\t\tStart router.\n");
	printf("\tstop\t\tStop router for now.\n");
}

void Interactor::printHead(){
	if (this->router != NULL) {
		if (this->router->workStatus == WorkStatus_Stop) {
			printf("stopped");
		}
		else if (this->router->workStatus == WorkStatus_Active) {
			printf("active");
		}
		else if (this->router->workStatus == WorkStatus_Close) {
			printf("closed");
		}
	}
	printf("$");
}

char * Interactor::getInput() {
	memset(this->input, 0, _BOBLI_INTERACTOR_H_INPUT_LEN);
	if (fgets(this->input, _BOBLI_INTERACTOR_H_INPUT_LEN - 2, stdin) == NULL){
		return NULL;
	}
	if (this->input[strlen(this->input) - 1] == '\n')
		this->input[strlen(this->input) - 1] = '\0';
	return this->input;
}

int Interactor::parseInput(char * _input_){
	int argc;
	char** argv = this->split(&argc, _input_);
	if (argc == 0) {
		return 1;
	}
	if (strcmp(argv[0], "router") != 0) {
		return 0;
	}
	if (strcmp(argv[1], "add") == 0) {
		// 添加路由表项
		return this->addRecord(argc, argv) == -1 ? 0 : 1;
	}
	else if (strcmp(argv[1], "del") == 0) {
		// 删除路由表项
		return this->delRecord(argc, argv) == -1 ? 0 : 1;
	}
	else if (strcmp(argv[1], "help") == 0) {
		this->printHelp();
		return 1;
	}
	else if (strcmp(argv[1], "print") == 0) {
		// 打印...
		return this->printSomething(argc, argv) == -1 ? 0 : 1;
	}
	else if (strcmp(argv[1], "quit") == 0) {
		// 退出程序并关闭路由器
		delete this->router;
		return -1;
	}
	else if (strcmp(argv[1], "start") == 0) {
		// 激活路由器
		this->router->start();
		return 1;
	}
	else if (strcmp(argv[1], "stop") == 0) {
		// 暂停路由器
		this->router->stop();
		return 1;
	}
	else {
		return 0;
	}
}

char** Interactor::split(int* argc, char* _input_){
	char* argv[256];
	char last = ' ';
	*argc = 0;
	argv[0] = (char *)_input_;
	int len = strlen(_input_);
	for (int i = 0; i < len; i = i + 1) {
		if ((_input_[i] == ' ' || i + 1 == len) && last != '\0') {
			*argc = *argc + 1;
		}
		if (_input_[i] == ' ') {
			_input_[i] = '\0';
			argv[*argc] = (char*)(_input_ + i + 1);
		}
		last = _input_[i];
	}
	return argv;
}
