#include "Router.h"

int Router::find(){
	for (int i = 0; i < _BOBLI_ROUTER_H_TABLE_LEN; i = i + 1) {
		if (this->table[i].valid == 0)
			return i;
	}
	return -1;
}

DWORD WINAPI Router::workThread(LPVOID lpParam){
	Router* router_p = (Router*)lpParam;
	int counter_1 = 0;
	while (router_p->workStatus != WorkStatus_Close) {
		counter_1 = counter_1 + 1;
		if (router_p->workStatus == WorkStatus_Stop) {
			Sleep(500);
			continue;
		}
		if (counter_1 > 30000) {
			clearMacTable(router_p);
			counter_1 = 0;
		}
		Sleep(1);
		capNext(router_p);
	}
	return 0;
}

void Router::capNext(Router* router_p){
	struct pcap_pkthdr* pcap_header;
	const u_char* pcap_data;
	int n = pcap_next_ex(router_p->handle, &pcap_header, &pcap_data);
	EthernetHeader_t* ethheader = (EthernetHeader_t*)pcap_data;
	if (n <= 0) {
		return;
	}
	if (ethheader->FrameType == htons(0x0800)) {
		if (checkIP((struct IPFrame*)pcap_data)) {
			// 检查校验和
			matchTable(router_p, pcap_header, pcap_data);
		}
	}
	else if (ethheader->FrameType == htons(0x0806)) {
		dealARP(router_p, pcap_header, pcap_data);
	}
}

void Router::matchTable(Router* router_p, pcap_pkthdr* pcap_header, const u_char* pcap_data){
	IPFrame* IP = (IPFrame*)pcap_data;
	IPAddr_t DesIP = IP->IP_header.DesIP;
	IPAddr_t next = 0;
	int maskLen = 0;
	for (int i = 0; i < _BOBLI_ROUTER_H_TABLE_LEN; i = i + 1) {
		// 匹配最长前缀
		int matchLen = match(&(router_p->table[i]), DesIP);
		if (matchLen > maskLen) {
			maskLen = matchLen;
			next = router_p->table[i].record.NextHop;
		}
	}
	forward(router_p, pcap_header, pcap_data, next);
}

int Router::match(MyRouter_Record* _record_, IPAddr_t _IP_){
	IPAddr_t net = _IP_ & _record_->record.NetMask;
	if (net == _record_->record.DesIP && _record_->valid > 0) {
		// 匹配单个表项
		return _record_->maskLen;
	}
	return -1;
}

void Router::dealARP(Router* router_p, pcap_pkthdr* pcap_header, const u_char* pcap_data){
	// 记录日志
	// ARPlog(router_p, pcap_header, pcap_data);
	struct ARPFrame* ARP = (struct ARPFrame*)pcap_data;
	// 记录ARP
	for (int i = 0; i < _BOBLI_ROUTER_H_MACTABLE_LEN; i = i + 1) {
		if (router_p->macTable[i].valid) {
			if (router_p->macTable[i].IP == ARP->ARP_header.SrcIP) {
				copyMAC(&(router_p->macTable[i].MAC), &(ARP->ARP_header.SrcHardwareMAC));
				return;
			}
			continue;
		}
		else {
			router_p->macTable[i].IP = ARP->ARP_header.SrcIP;
			copyMAC(&(router_p->macTable[i].MAC), &(ARP->ARP_header.SrcHardwareMAC));
			router_p->macTable[i].valid = 1;
			return;
		}
	}

}

void Router::forward(Router* router_p, pcap_pkthdr* pcap_header, const u_char* pcap_data, IPAddr_t _next_){
	struct IPFrame* original = (struct IPFrame*)pcap_data;
	MACAddr_t DesMAC;
	// 从本机发出的报文不进行处理
	if (original->Eth_header.SrcMAC.MAC[0] == router_p->MAC.MAC[0] &&
		original->Eth_header.SrcMAC.MAC[1] == router_p->MAC.MAC[1] &&
		original->Eth_header.SrcMAC.MAC[2] == router_p->MAC.MAC[2] &&
		original->Eth_header.SrcMAC.MAC[3] == router_p->MAC.MAC[3] &&
		original->Eth_header.SrcMAC.MAC[4] == router_p->MAC.MAC[4] &&
		original->Eth_header.SrcMAC.MAC[5] == router_p->MAC.MAC[5]) {
		return;
	}
	// TTL超时判断
	if (original->IP_header.TTL == 1 || original->IP_header.TTL == 0) {
		sendICMP(router_p, pcap_header, pcap_data);
		return;
	}
	// 获取不到MAC直接丢弃
	if (getMAC(&DesMAC, router_p, _next_ == 0 ? original->IP_header.DesIP : _next_) < 0) {
		return;
	}
	// 从const复制数据以更改
	u_char* forward_data = (u_char*)malloc(pcap_header->len);
	bstrcpy(forward_data, pcap_data, pcap_header->len);
	struct IPFrame* forward_IP = (struct IPFrame*)forward_data;
	// 数据处理
	copyMAC(&(forward_IP->Eth_header.DesMAC), &DesMAC);                                          // 写入目的MAC
	copyMAC(&(forward_IP->Eth_header.SrcMAC), &router_p->MAC);                                   // 写入源MAC
	forward_IP->IP_header.TTL = forward_IP->IP_header.TTL - 1;                                   // TTL减1
	forward_IP->IP_header.Checksum = 0;
	forward_IP->IP_header.Checksum = ~computeCheckSum((u_char*)&(forward_IP->IP_header),
		                                              (forward_IP->IP_header.Ver_HLen % 0x10)*4);// 校验和计算
	pcap_sendpacket(router_p->handle, (const u_char*)forward_data, pcap_header->len);            // 发送
	IPlog(router_p, pcap_data, forward_data, _next_);                                            // 写入日志
	free(forward_data);
}

IPAddr_t Router::getRouterIP(Router* router_p, IPAddr_t IP){
	for (int i = 0; i < _BOBLI_ROUTER_H_MAX_BIND_IP && router_p->bindIPs[i] != 0; i = i + 1) {
		for (int j = 0; j < _BOBLI_ROUTER_H_TABLE_LEN; j = j + 1) {
			if ((IP & router_p->table[j].record.DesIP) == (router_p->bindIPs[i] & router_p->table[j].record.DesIP)
				&& router_p->table[j].valid > 0) {
				return router_p->bindIPs[i];
			}
		}
	}
	return router_p->bindIPs[0];
}

int Router::getMAC(MACAddr_t* _DesMAC_, Router* router_p, IPAddr_t _IP_){
	for (int i = 0; i < _BOBLI_ROUTER_H_MACTABLE_LEN; i = i + 1) {
		if (router_p->macTable[i].valid && _IP_ == router_p->macTable[i].IP) {
			copyMAC(_DesMAC_, &(router_p->macTable[i].MAC));
			return i;
		}
	}
	sendARP(router_p->handle, &(router_p->macTable[0].MAC), router_p->macTable[0].IP, _IP_);
	_DesMAC_->MAC[0] = 0xff;
	_DesMAC_->MAC[1] = 0xff;
	_DesMAC_->MAC[2] = 0xff;
	_DesMAC_->MAC[3] = 0xff;
	_DesMAC_->MAC[4] = 0xff;
	_DesMAC_->MAC[5] = 0xff;
	return -1;
}

void Router::sendARP(pcap_t* handle, MACAddr_t* _SrcMAC_, IPAddr_t _SrcIP_, IPAddr_t _DesIP_){
	struct ARPFrame ARP;
	ARP.Eth_header.FrameType = htons(0x0806);
	copyMAC(&(ARP.Eth_header.SrcMAC), _SrcMAC_);
	ARP.Eth_header.DesMAC.MAC[0] = 0xff;
	ARP.Eth_header.DesMAC.MAC[1] = 0xff;
	ARP.Eth_header.DesMAC.MAC[2] = 0xff;
	ARP.Eth_header.DesMAC.MAC[3] = 0xff;
	ARP.Eth_header.DesMAC.MAC[4] = 0xff;
	ARP.Eth_header.DesMAC.MAC[5] = 0xff;
	ARP.ARP_header.HardwareType = htons(0x0001); // Ethernet
	ARP.ARP_header.ProtocolType = htons(0x0800); // IPv4
	ARP.ARP_header.HardwareLen = 6;
	ARP.ARP_header.ProtocolLen = 4;
	ARP.ARP_header.Operation = htons(0x0001); // Operation is get (ARP)
	copyMAC(&(ARP.ARP_header.SrcHardwareMAC), _SrcMAC_);
	ARP.ARP_header.SrcIP = _SrcIP_;
	ARP.ARP_header.DesIP = _DesIP_;
	pcap_sendpacket(handle, (const u_char*)&ARP, sizeof(struct ARPFrame));
}

void Router::sendICMP(Router* router_p, pcap_pkthdr* pcap_header, const u_char* pcap_data){
	IPFrame* original_IP = (IPFrame*)pcap_data;
	MACAddr_t DesMAC;
	// 获取不到MAC直接丢弃
	if (getMAC(&DesMAC, router_p, original_IP->IP_header.SrcIP) < 0) {
		return;
	}
	u_char* forward_data = (u_char*)malloc(sizeof(IPFrame) + sizeof(ICMPHeader_t) + sizeof(IPHeader_t) + 8);
	IPFrame* forward_IP = (IPFrame*)forward_data;
	ICMPHeader_t* ICMP = (ICMPHeader_t*)(forward_data + sizeof(IPFrame));
	// 拷贝
	bstrcpy(forward_data, pcap_data, sizeof(IPFrame) + sizeof(ICMPHeader_t) + sizeof(IPHeader_t) + 8);
	// 以太网报文
	copyMAC(&(forward_IP->Eth_header.DesMAC), &DesMAC);
	copyMAC(&(forward_IP->Eth_header.SrcMAC), &(router_p->MAC));
	// IP报文
	forward_IP->IP_header.TotalLen = htons(sizeof(IPHeader_t) + sizeof(ICMPHeader_t) + sizeof(IPHeader_t) + 8);
	forward_IP->IP_header.TTL = 64;
	forward_IP->IP_header.DesIP = original_IP->IP_header.SrcIP;
	forward_IP->IP_header.SrcIP = getRouterIP(router_p, original_IP->IP_header.SrcIP);
	forward_IP->IP_header.Checksum = 0;
	ICMP->Type = 11;
	ICMP->Code = 0;
	ICMP->Checksum = 0;
	ICMP->Options = 0;
	bstrcpy((u_char*)(forward_data + sizeof(IPFrame) + sizeof(ICMPHeader_t)),
		    (u_char*)(pcap_data + sizeof(EthernetHeader_t)),
		    sizeof(IPHeader_t) + 8);
	ICMP->Checksum = ~computeCheckSum((u_char*)(ICMP), sizeof(ICMPHeader_t) + sizeof(IPHeader_t) + 8);
	forward_IP->IP_header.Checksum = ~computeCheckSum((u_char*)(forward_data + sizeof(EthernetHeader_t)),
		                                              sizeof(IPHeader_t));
	pcap_sendpacket(router_p->handle,
		            (const u_char*)forward_data,
		            sizeof(IPFrame) + sizeof(ICMPHeader_t) + sizeof(IPHeader_t) + 8);
	free(forward_data);
}

void Router::clearMacTable(Router* router_p){
	for (int i = 1; i < _BOBLI_ROUTER_H_MACTABLE_LEN; i = i + 1) {
		router_p->macTable[i].valid = router_p->macTable[i].valid == 2 ? 2 : 0;
	}
}

void Router::ARPlog(Router* router_p, pcap_pkthdr* pcap_header, const u_char* pcap_data){
	// 记录日志
	ARPFrame *ARP = (ARPFrame*)pcap_data;
	char log[_BOBLI_ROUTER_H_LOG_LEN] = "[receive ARP] SrcIP:";
	char str[50];
	uint8_t* IP = (uint8_t*)&(ARP->ARP_header.SrcIP);
	// SrcIP
	_itoa(IP[0], str, 10); strcat(log, str); strcat(log, ".");
	_itoa(IP[1], str, 10); strcat(log, str); strcat(log, ".");
	_itoa(IP[2], str, 10); strcat(log, str); strcat(log, ".");
	_itoa(IP[3], str, 10); strcat(log, str); strcat(log, " SrcMAC:");
	_itoa(ARP->ARP_header.SrcHardwareMAC.MAC[0], str, 16); strcat(log, str); strcat(log, ":");
	_itoa(ARP->ARP_header.SrcHardwareMAC.MAC[1], str, 16); strcat(log, str); strcat(log, ":");
	_itoa(ARP->ARP_header.SrcHardwareMAC.MAC[2], str, 16); strcat(log, str); strcat(log, ":");
	_itoa(ARP->ARP_header.SrcHardwareMAC.MAC[3], str, 16); strcat(log, str); strcat(log, ":");
	_itoa(ARP->ARP_header.SrcHardwareMAC.MAC[4], str, 16); strcat(log, str); strcat(log, ":");
	_itoa(ARP->ARP_header.SrcHardwareMAC.MAC[5], str, 16); strcat(log, str); strcat(log, "\r\n");
	writelog(router_p, log, strlen(log));
}

void Router::IPlog(Router* router_p, const u_char* _old_, u_char* _new_, IPAddr_t _next_){
	IPFrame* ol = (IPFrame*)_old_;
	IPFrame* ne = (IPFrame*)_new_;
	char log[_BOBLI_ROUTER_H_LOG_LEN] = "[receive IP] SrcIP:";
	char str[50];
	uint8_t* IP = (uint8_t*)&(ol->IP_header.SrcIP);
	_itoa(IP[0], str, 10); strcat(log, str); strcat(log, ".");
	_itoa(IP[1], str, 10); strcat(log, str); strcat(log, ".");
	_itoa(IP[2], str, 10); strcat(log, str); strcat(log, ".");
	_itoa(IP[3], str, 10); strcat(log, str); strcat(log, " DesIP:");
	IP = (uint8_t*)&(ol->IP_header.DesIP);
	_itoa(IP[0], str, 10); strcat(log, str); strcat(log, ".");
	_itoa(IP[1], str, 10); strcat(log, str); strcat(log, ".");
	_itoa(IP[2], str, 10); strcat(log, str); strcat(log, ".");
	_itoa(IP[3], str, 10); strcat(log, str); strcat(log, " SrcMAC:");
	_itoa(ol->Eth_header.SrcMAC.MAC[0], str, 16); strcat(log, str); strcat(log, ":");
	_itoa(ol->Eth_header.SrcMAC.MAC[1], str, 16); strcat(log, str); strcat(log, ":");
	_itoa(ol->Eth_header.SrcMAC.MAC[2], str, 16); strcat(log, str); strcat(log, ":");
	_itoa(ol->Eth_header.SrcMAC.MAC[3], str, 16); strcat(log, str); strcat(log, ":");
	_itoa(ol->Eth_header.SrcMAC.MAC[4], str, 16); strcat(log, str); strcat(log, ":");
	_itoa(ol->Eth_header.SrcMAC.MAC[5], str, 16); strcat(log, str); strcat(log, " DesMAC:");
	_itoa(ol->Eth_header.DesMAC.MAC[0], str, 16); strcat(log, str); strcat(log, ":");
	_itoa(ol->Eth_header.DesMAC.MAC[1], str, 16); strcat(log, str); strcat(log, ":");
	_itoa(ol->Eth_header.DesMAC.MAC[2], str, 16); strcat(log, str); strcat(log, ":");
	_itoa(ol->Eth_header.DesMAC.MAC[3], str, 16); strcat(log, str); strcat(log, ":");
	_itoa(ol->Eth_header.DesMAC.MAC[4], str, 16); strcat(log, str); strcat(log, ":");
	_itoa(ne->Eth_header.DesMAC.MAC[5], str, 16); strcat(log, str); strcat(log, "\r\n[forward IP] NextHop:");
	IP = (uint8_t*)&_next_;
	_itoa(IP[0], str, 10); strcat(log, str); strcat(log, ".");
	_itoa(IP[1], str, 10); strcat(log, str); strcat(log, ".");
	_itoa(IP[2], str, 10); strcat(log, str); strcat(log, ".");
	_itoa(IP[3], str, 10); strcat(log, str); strcat(log, " SrcMAC:");
	_itoa(ne->Eth_header.SrcMAC.MAC[0], str, 16); strcat(log, str); strcat(log, ":");
	_itoa(ne->Eth_header.SrcMAC.MAC[1], str, 16); strcat(log, str); strcat(log, ":");
	_itoa(ne->Eth_header.SrcMAC.MAC[2], str, 16); strcat(log, str); strcat(log, ":");
	_itoa(ne->Eth_header.SrcMAC.MAC[3], str, 16); strcat(log, str); strcat(log, ":");
	_itoa(ne->Eth_header.SrcMAC.MAC[4], str, 16); strcat(log, str); strcat(log, ":");
	_itoa(ne->Eth_header.SrcMAC.MAC[5], str, 16); strcat(log, str); strcat(log, " DesMAC:");
	_itoa(ne->Eth_header.DesMAC.MAC[0], str, 16); strcat(log, str); strcat(log, ":");
	_itoa(ne->Eth_header.DesMAC.MAC[1], str, 16); strcat(log, str); strcat(log, ":");
	_itoa(ne->Eth_header.DesMAC.MAC[2], str, 16); strcat(log, str); strcat(log, ":");
	_itoa(ne->Eth_header.DesMAC.MAC[3], str, 16); strcat(log, str); strcat(log, ":");
	_itoa(ne->Eth_header.DesMAC.MAC[4], str, 16); strcat(log, str); strcat(log, ":");
	_itoa(ne->Eth_header.DesMAC.MAC[5], str, 16); strcat(log, str); strcat(log, "\r\n");
	writelog(router_p, log, strlen(log));
}

void Router::writelog(Router* router_p, char* log, int len){
	//router_p->mtx.lock();
	fwrite(log, len, 1, router_p->logfp);
	//router_p->mtx.unlock();
}

Router::Router(pcap_t * _handle_) {
	// 清理路由表和MAC映射表
	memset(this->bindIPs, 0, sizeof(IPAddr_t)*_BOBLI_ROUTER_H_MAX_BIND_IP);
	memset(this->table, 0, sizeof(struct MyRouter_Record)*_BOBLI_ROUTER_H_TABLE_LEN);
	memset(this->macTable, 0, sizeof(struct IP_MAC_Record)*_BOBLI_ROUTER_H_MACTABLE_LEN);
	this->handle = _handle_;
	this->workThreadID = 0;
	this->workStatus = WorkStatus_Stop;
	// logfile
	this->logfp = fopen("./myrouter.log", "w+");
	// 工作线程
	this->workHandle = CreateThread(NULL,					// 默认安全属性
									0,						// 默认的栈大小
									workThread,				// 线程函数
									this,					// 线程参数
									0,						// 默认flag
									&(this->workThreadID));	// 返回线程ID
}

Router::~Router() {
	this->workStatus = WorkStatus_Close;
	WaitForSingleObject(this->workHandle, INFINITE);
	fclose(this->logfp);
}

void Router::bind(IPAddr_t IP){
	for (int i = 0; i < _BOBLI_ROUTER_H_MAX_BIND_IP; i = i + 1) {
		if (this->bindIPs[i] == 0) {
			this->bindIPs[i] = IP;
			return;
		}
	}
}

void Router::start(){
	this->workStatus = WorkStatus_Active;
}

void Router::stop() {
	this->workStatus = WorkStatus_Stop;
}

int Router::addRecord(struct Router_Record * _record_, int flag){
	int pos = this->find();
	if (pos < 0) {
		return -1;
	}
	this->table[pos].record.DesIP = _record_->DesIP & _record_->NetMask;
	this->table[pos].record.NetMask = _record_->NetMask;
	this->table[pos].record.NextHop = _record_->NextHop;
	this->table[pos].valid = flag;
	this->table[pos].maskLen = bitCount(_record_->NetMask);
	return pos;
}

int Router::delRecord(int _No_){
	int No = 0;
	for (int i = 0; i < _BOBLI_ROUTER_H_TABLE_LEN; i = i + 1) {
		if (this->table[i].valid != 0) {
			No = No + 1;
		}
		if (_No_ == No && this->table[i].valid != 2) {
			this->table[i].valid = 0;
			return i;
		}
	}
	return -1;
}

int Router::addMac(MACAddr_t* MAC, IPAddr_t IP, int valid){
	for (int i = 0; i < _BOBLI_ROUTER_H_MACTABLE_LEN; i = i + 1) {
		if (this->macTable[i].valid == 0) {
			copyMAC(&(this->macTable[i].MAC), MAC);
			this->macTable[i].IP = IP;
			this->macTable[i].valid = valid;
			return i;
		}
	}
	return -1;
}

int Router::delMac(int _No_){
	int No = 0;
	for (int i = 0; i < _BOBLI_ROUTER_H_MACTABLE_LEN; i = i + 1) {
		if (this->macTable[i].valid != 0) {
			No = No + 1;
		}
		if (_No_ == No && this->macTable[i].valid != 2) {
			this->macTable[i].valid = 0;
			return i;
		}
	}
	return -1;
}

void Router::clearRecord(Router* router_p){
	for (int i = 1; i < _BOBLI_ROUTER_H_TABLE_LEN; i = i + 1) {
		router_p->table[i].valid = router_p->table[i].valid == 2 ? 2 : 0;
	}
}

void Router::printInfo(FILE* _fp_){
	fprintf(_fp_, "IPs binded to this device are as below.\r\n");
	for (int i = 0; i < _BOBLI_ROUTER_H_MAX_BIND_IP && this->bindIPs[i] != 0; i = i + 1) {
		uint8_t* IP = (uint8_t*)&(this->bindIPs[i]);
		fprintf(_fp_, "\t%3d.%3d.%3d.%3d\r\n", IP[0], IP[1], IP[2], IP[3]);
	}
	fprintf(_fp_, "MAC binded to this device is as below.\r\n");
	fprintf(_fp_, "\t%2x.%2x.%2x.%2x.%2x.%2x\r\n", this->MAC.MAC[0], 
		                                           this->MAC.MAC[1], 
		                                           this->MAC.MAC[2],
		                                           this->MAC.MAC[3],
		                                           this->MAC.MAC[4],
		                                           this->MAC.MAC[5]);
}

void Router::printRouter(FILE * _fp_){
	int recordNo = 1;
	fprintf(_fp_, "No \tDesIP                NetMask              NextHop\n");
	for (int i = 0; i < _BOBLI_ROUTER_H_TABLE_LEN; i = i + 1) {
		if (this->table[i].valid > 0) {
			uint8_t* IP;
			fprintf(_fp_, "No.%d\t", recordNo);
			IP = (uint8_t*)&(this->table[i].record.DesIP);
			fprintf(_fp_, "%3d.%3d.%3d.%3d      ", IP[0], IP[1], IP[2], IP[3]);
			IP = (uint8_t*)&(this->table[i].record.NetMask);
			fprintf(_fp_, "%3d.%3d.%3d.%3d      ", IP[0], IP[1], IP[2], IP[3]);
			IP = (uint8_t*)&(this->table[i].record.NextHop);
			fprintf(_fp_, "%3d.%3d.%3d.%3d", IP[0], IP[1], IP[2], IP[3]);
			fprintf(_fp_, this->table[i].valid == 1 ? "\r\n" : "(unchangable)\r\n");
			recordNo = recordNo + 1;
		}
	}
}

void Router::printMAC(FILE* _fp_){
	int recordNo = 1;
	fprintf(_fp_, "No \tIP                   MAC\n");
	for (int i = 0; i < _BOBLI_ROUTER_H_MACTABLE_LEN; i = i + 1) {
		if (this->macTable[i].valid > 0) {
			uint8_t* IP, *MAC;
			fprintf(_fp_, "No.%d\t", recordNo);
			IP = (uint8_t*)&(this->macTable[i].IP);
			fprintf(_fp_, "%3d.%3d.%3d.%3d      ", IP[0], IP[1], IP[2], IP[3]);
			MAC = (uint8_t*)&(this->macTable[i].MAC.MAC);
			fprintf(_fp_, "%2x.%2x.%2x.%2x.%2x.%2x\n", MAC[0], MAC[1], MAC[2], MAC[3], MAC[4], MAC[5]);
			recordNo = recordNo + 1;
		}
	}
}

void Router::printLog(FILE* _fp_){
	char buff[1025];
	memset(buff, 0, 1025);
	//this->mtx.lock();
	if (this->logfp != NULL) {
		long curpos = ftell(this->logfp);
		fseek(this->logfp, 0, SEEK_END);
		long filesize = ftell(this->logfp);
		fseek(this->logfp, 0, SEEK_SET);
		for (long left = filesize; left > 0; left = left - 1024) {
			fread(buff, 1024, 1, this->logfp);
			printf("%s", buff);
		}
		fseek(this->logfp, curpos, SEEK_SET);
	}
	//this->mtx.unlock();
}
