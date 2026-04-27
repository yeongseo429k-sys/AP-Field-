#include <pcap.h>        // 패킷 캡처
#include <cstdio>        // printf, fprintf (C의 <stdio.h>에 해당)
#include <cstdint>       // uint8_t 등 (C의 <stdint.h>에 해당)
#include <iostream>      // std::cout (usage 함수에서 사용)
#include <arpa/inet.h>   // ntohs()

void usage() {
	std::cout << "syntax: pcap-test <interface>\n";
	std::cout << "sample: pcap-test wlan0\n";
}

struct Param {
	char* dev_;
};

Param param = {
	.dev_ = NULL
};

#pragma pack(push,1)
struct EthHeader {
	uint8_t dstMac[6];
	uint8_t srcMac[6];
	uint16_t ethType;
};

struct IPv4Header {
	uint8_t verihl; //version + IHL
	uint8_t tos;
	uint16_t totLen;
	uint16_t iden;
	uint16_t flagOff; //flag + Fragment offset
	uint8_t ttl;
	uint8_t protocol;
	uint16_t checksum;
	uint32_t srcIpAdd;
	uint32_t dstIpAdd;
};

struct TCPHeader {
	uint16_t srcPort;
	uint16_t dstPort;
	uint32_t seqNum;
	uint32_t ackNum;
	uint8_t offResv; // Data Offset + Reserved
	uint8_t flags; //CWR, ECE URG, ACK, PSH, RST, SYN, FIN
	uint16_t window;
	uint16_t checksum;
	uint16_t urgPointer;
};
#pragma pack(pop)



bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);
		struct EthHeader* eth = (struct EthHeader*)packet;
		if (ntohs(eth->EthType) != 0x0800){
			continue;
		}



		struct IPv4Header* ip = (struct IPv4Header*)(packet + sizeof(struct EthHeader));
		if (ip-> protocol != 6){
			continue;
		}

		       	

		int IPHeaderLen = (ip -> Ver_Ihl & 0x0F) *4;
		struct TCPHeader* tcp = (struct TCPHeader*)((uint8_t*)ip + IPHeaderLen);
		int TCPHeaderLen = ((tcp->Off_Resv >> 4) & 0x0F) *4;

		int payloadLen = ntohs(ip -> totLen) - IPHeaderLen - TCPHeaderLen;
		const uint8_t* payload = (const uint8_t*)tcp + TCPHeaderLen;

		uint8_t* SrcIP = (uint8_t*)&ip -> srcIPAdd;
		uint8_t* DstIP = (uint8_t*) &ip -> dstIPAdd;

		printf("Source Mac : %02x:%02x:%02x:%02x:%02x:%02x\n", eth -> srcMac[0], eth -> srcMac[1], eth -> srcMac[2], eth-> srcMac[3], eth-> srcMac[4], eth-> srcMac[5]);
		printf("Destination Mac : %02x:%02x:%02x:%02x:%02x:%02x\n", eth -> dstMac[0], eth-> dstMac[1], eth -> dstMac[2], eth-> dstMac[3], eth -> dstMac[4], eth-> dstMac[5]);
		printf("Sroucr IP : %d.%d.%d.%d\n", SrcIP[0], SrcIP[1], SrcIP[2], SrcIP[3]);
		printf("Destination IP : %d.%d.%d.%d\n", DstIP[0], DstIP[1], DstIP[2], DstIP[3]);
		printf("Source Port : %d\n", ntohs(tcp->srcPort));
		printf("Destination Port : %d\n", ntohs(tcp->dstPort));

		int print_len = payloadLen > 20 ? 20 : payloadLen;
		printf("payload:");
		for (int i = 0 ; i< print_len; i++){
			printf("%02x", payload[i]);
				}
		printf("\n");
	}

	pcap_close(pcap);
}

