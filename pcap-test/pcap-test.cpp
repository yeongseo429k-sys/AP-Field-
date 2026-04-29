#include <pcap.h>
#include <cstdio>
#include <cstdint>
#include <iostream>
using namespace std;

void usage() {
    cout << "syntax: pcap-test <interface>\n";
    cout << "sample: pcap-test wlan0\n";
}

struct Param {
    char* dev_;
};

Param param = { nullptr };

#pragma pack(push, 1)
struct EthHeader {
    uint8_t dstMac[6];
    uint8_t srcMac[6];
    uint16_t ethType;

    uint16_t getEthType() { return ntohs(ethType); }

    void printMac(const uint8_t mac[6]) {
        printf("%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }

    void printSrcMac() {
        printf("Source Mac : ");
        printMac(srcMac);
        printf("\n");
    }

    void printDstMac() {
        printf("Destination Mac : ");
        printMac(dstMac);
        printf("\n");
    }
};

struct IPv4Header {
    uint8_t verihl;
    uint8_t tos;
    uint16_t totLen;
    uint16_t iden;
    uint16_t flagOff;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t srcIpAdd;
    uint32_t dstIpAdd;

    uint16_t getTotLen() { return ntohs(totLen); }
    int getHeaderLen() { return (verihl & 0x0F) * 4; }

    void printIp(uint32_t ipAddr) {
        uint8_t* ip = (uint8_t*)&ipAddr;
        printf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
    }

    void printSrcIp() {
        printf("Source IP : ");
        printIp(srcIpAdd);
        printf("\n");
    }

    void printDstIp() {
        printf("Destination IP : ");
        printIp(dstIpAdd);
        printf("\n");
    }
};

struct TCPHeader {
    uint16_t srcPort;
    uint16_t dstPort;
    uint32_t seqNum;
    uint32_t ackNum;
    uint8_t offResv;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgPointer;

    uint16_t getSrcPort() { return ntohs(srcPort); }
    uint16_t getDstPort() { return ntohs(dstPort); }
    int getHeaderLen() { return ((offResv >> 4) & 0x0F) * 4; }
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
    if (pcap == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        printf("%u bytes captured\n", header->caplen);

        EthHeader* eth = (EthHeader*)packet;
        if (eth->getEthType() != 0x0800) {
            continue;
        }

        IPv4Header* ip = (IPv4Header*)(packet + sizeof(EthHeader));
        if (ip->protocol != 6) {
            continue;
        }

        int IPHeaderLen = ip->getHeaderLen();
        TCPHeader* tcp = (TCPHeader*)((uint8_t*)ip + IPHeaderLen);
        int TCPHeaderLen = tcp->getHeaderLen();

        int payloadLen = ip->getTotLen() - IPHeaderLen - TCPHeaderLen;
        const uint8_t* payload = (const uint8_t*)tcp + TCPHeaderLen;

        eth->printSrcMac();
        eth->printDstMac();
        ip->printSrcIp();
        ip->printDstIp();
        printf("Source Port : %d\n", tcp->getSrcPort());
        printf("Destination Port : %d\n", tcp->getDstPort());

        int print_len = payloadLen > 20 ? 20 : payloadLen;
        printf("Payload : ");
        for (int i = 0; i < print_len; i++) {
            printf("%02x ", payload[i]);
        }
        printf("\n");
    }

    pcap_close(pcap);
}