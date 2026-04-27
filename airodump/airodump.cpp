#include <iostream>
#include <pcap.h>
#include <array>

#pragma pack(push,1)
//PWR 얻으려면 radiotapHeader에서 확인, 일단 보류 
struct radiotapHeader {
    uint8_t version;
    uint8_t pad;
    uint16_t len;
    uint32_t present;
};

//beaconframe 
struct IEEE80211Header {
    uint16_t frameControl;
    uint16_t duration;
    uint8_t dstAddr[6];
    uint8_t srcAddr[6];
    uint8_t bssid[6];
    uint16_t seqCtrl;
};

//bssid, ssid, beacon 테이블
using macAddr = std::array<uint8_t, 6>;
struct apInfo{
    macAddr bssid;
    std::string ssid;
    uint32_t beacons = 0;
};
#pragma pack(pop)

uint8_t fcType(uint16_t fc)    { return (fc >> 2) & 0x3; }
uint8_t fcSubtype(uint16_t fc) { return (fc >> 4) & 0xF; }

bool isBeacon(uint16_t fc) {
    return fcType(fc) == 0 && fcSubtype(fc) == 8;
}

//IEEE Wireless Mangament (fixedParam + taggedParam)
static const int beaconFixedParam = 12;

//ssid 파싱 
bool parseSsid(const uint8_t* body, int bodyLen, std::string& ssidResult){
    int pos = 0;
    while (pos + 2 <= bodyLen){
        uint8_t tagNum = body[pos];
        uint8_t tagLen = body[pos + 1];
        
        if (tagNum == 0){
            ssidResult.assign((const char*)&body[pos + 2], tagLen);
            return true;
        }
        pos += 2 + tagLen;
    }
    return false;
}

//pcap 열기
pcap_t* openHandle(const char* iface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(iface, 65536, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live: %s\n", errbuf);
        exit(1);
    }
    return handle;
}

//비콘 

//결과물 출력
void display() {
    printf("\033[H\033[2J");
    printf(" %-18s  %8s  %s\n", "BSSID", "Beacons", "ESSID");
    for (auto& [mac, info] : apMap) {
        printf(" %02X:%02X:%02X:%02X:%02X:%02X  %8u  %s\n",
               mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
               info.beacons, info.ssid.c_str());
    }
    fflush(stdout);
}


int main() {

}