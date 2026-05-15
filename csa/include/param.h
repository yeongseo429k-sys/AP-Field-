#pragma once

#include <string>
#include <pcap.h>
#include "mac.h"

struct Args {
    std::string iface;
    Mac apMac;
    Mac staMac;
    bool hasStation;
};

extern Args args_;

void    usage(const char* prog);
bool    parseArgs(int argc, char* argv[]);
void    printInfo();
pcap_t* openHandle(const std::string& iface);