#include <cstdio>
#include "param.h"

Args args_;

void usage(const char* prog) {
    fprintf(stderr,
            "syntax : %s <interface> <ap mac> [<station mac>]\n"
            "sample : %s mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n", prog, prog);
}

bool parseArgs(int argc, char* argv[]) {
    if (argc < 3) return false;
    args_.iface = argv[1];
    args_.apMac = Mac(argv[2]);
    args_.hasStation = false;
    if (argc >= 4) {
        args_.staMac = Mac(argv[3]);
        args_.hasStation = true;
    }
    return true;
}

void printInfo() {
    printf("AP : %s\n", args_.apMac.toString().data());
    if (args_.hasStation)
        printf("STA : %s\n", args_.staMac.toString().data());
    printf("Iface : %s\n\n", args_.iface.data());
}

pcap_t* openHandle(const std::string& iface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(iface.data(), BUFSIZ, 1, 1, errbuf);
    if (!handle)
        fprintf(stderr, "pcap_open_live(%s): %s\n", iface.data(), errbuf);
    return handle;
}