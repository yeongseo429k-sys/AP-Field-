#include <cstdio>
#include "dot11.h"

Dot11Hdr  dot11Hdr_;
BeaconHdr beaconHdr_;

void initCsaTag(BeaconHdr::CsaTag* tag) {
    tag->number             = 0x25;
    tag->length             = 0x03;
    tag->channelSwitchMode  = 0x01;
    tag->newChannel         = 0x0B;
    tag->channelSwitchCount = 0x03;
}

void setAddr1(uint8_t* packet, int radiotapLen, const Mac& addr1) {
    // addr1 위치 = radiotap 끝 + subtype(1) + ver_type(1) + duration(2) = +4
    memcpy(packet + radiotapLen + 4, addr1.mac_, 6);
}

bool captureBeacon(pcap_t* handle, const Mac& apMac,
                   int radiotapLen, uint8_t* buf, int* len) {
    printf("[*] Waiting for beacon from %s ...\n", apMac.toString().data());

    while (true) {
        struct pcap_pkthdr* header;
        const uint8_t* pkt;
        int res = pcap_next_ex(handle, &header, &pkt);
        if (res == 0) continue;
        if (res < 0) return false;

        if ((int)header->caplen < radiotapLen + (int)sizeof(Dot11Hdr)) continue;

        // radiotap 뒤에 Dot11Hdr를 memcpy로 읽기
        Dot11Hdr dot11;
        memcpy(&dot11, pkt + radiotapLen, sizeof(Dot11Hdr));

        if (!dot11.is_beacon()) continue;

        // addr2 = 송신자(AP)
        if (!(dot11.addr2_ == apMac)) continue;

        *len = (int)header->caplen;
        memcpy(buf, pkt, *len);
        printf("[+] Beacon captured (%d bytes)\n", *len);
        return true;
    }
}

int buildCsaPacket(const uint8_t* captured, int capLen,
                   int radiotapLen, bool fcs,
                   uint8_t* outBuf, int outBufSize) {
    if (fcs)
        capLen -= 4;

    // tagged params 시작 = radiotap + Dot11Hdr + BeaconHdr::Fix
    int tagStart = radiotapLen + (int)sizeof(Dot11Hdr) + (int)sizeof(BeaconHdr::Fix);
    if (tagStart > capLen) return 0;

    BeaconHdr::CsaTag csa;
    initCsaTag(&csa);

    // tag number 정렬 유지하며 삽입 지점 찾기
    int insertPos = tagStart;
    int pos = tagStart;
    while (pos + 2 <= capLen) {
        uint8_t tagNum = captured[pos];
        uint8_t tagLen = captured[pos + 1];

        if (tagNum >= csa.number) {
            // 이미 CSA가 있으면 교체
            if (tagNum == csa.number) {
                int beforeLen  = pos;
                int afterStart = pos + 2 + tagLen;
                int afterLen   = capLen - afterStart;
                memcpy(outBuf, captured, beforeLen);
                memcpy(outBuf + beforeLen, &csa, sizeof(csa));
                memcpy(outBuf + beforeLen + sizeof(csa),
                       captured + afterStart, afterLen);
                return beforeLen + (int)sizeof(csa) + afterLen;
            }
            insertPos = pos;
            break;
        }
        pos += 2 + tagLen;
        insertPos = pos;
    }

    if (pos + 2 > capLen)
        insertPos = capLen;

    int totalLen = capLen + (int)sizeof(csa);
    if (totalLen > outBufSize) return 0;

    memcpy(outBuf, captured, insertPos);
    memcpy(outBuf + insertPos, &csa, sizeof(csa));
    memcpy(outBuf + insertPos + sizeof(csa),
           captured + insertPos, capLen - insertPos);

    return totalLen;
}