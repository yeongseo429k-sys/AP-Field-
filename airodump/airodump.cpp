#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <map>
#include <pcap.h>

#include "mac.h"

using namespace std;

#pragma pack(push, 1)

struct RadiotapHeader {
    uint8_t  revision_;
    uint8_t  pad_;
    uint16_t len_;
    uint32_t present_; //4바이트씩 3개 

    uint16_t rtLen() const { return len_; } //radiotap헤더 길이 
};

// 802.11 공통 (frame control + duration)
struct IEEE80211 {
    uint16_t frameControl_;
    uint16_t duration_;

    uint8_t type()    const { return (frameControl_ >> 2) & 0x3; }
    uint8_t subtype() const { return (frameControl_ >> 4) & 0xF; }
    bool isBeacon()   const { return type() == 0 && subtype() == 8; }
};

// 관리 프레임용 (address 1/2/3 + seqCtrl)
struct IEEE80211Header : public IEEE80211 {
    uint8_t dstAddr_[6];
    uint8_t srcAddr_[6];
    uint8_t BSSID_[6];  
    uint16_t seqCtrl_;

    Mac bssid() const { return Mac(BSSID_); }
};

// 비콘 고정 파라미터 (12바이트)
struct fixedParam {
    uint64_t timestamp_;
    uint16_t interval_;
    uint16_t capability_;
};

// 태그 하나의 헤더 (번호 + 길이) //ssid는 길이에 따라 달라지기 때문에 넣지 않음 
struct taggedParam {
    uint8_t number_;
    uint8_t length_;

    enum Id : uint8_t {
        SSID = 0,
        DS_PARAM = 3, // wifi의 ds_param의 값은 3 //나중에 채널번호도 할 수 있을지도 모르니까
    };

    const uint8_t* value() const {
        return reinterpret_cast<const uint8_t*>(this) + 2;
    }
};

#pragma pack(pop)

// AP 정보
struct ApInfo {
    Mac bssid;
    std::string ssid;
    int channel   = -1;
    int8_t signal = 0; //t
    uint32_t beacons = 0;
};

// 전역 AP 맵
static map<Mac, ApInfo> apMap;

// static const RtFieldInfo rtFieldTable[] = {
//     {8, 8},  // 0: TSFT
//     {1, 1},  // 1: FLAGS
//     {1, 1},  // 2: RATE
//     {4, 2},  // 3: CHANNEL
//     {2, 1},  // 4: FHSS
//     {1, 1},  // 5: DBM_ANTSIGNAL  ← 나중에 가져와야 할 값 
//     {1, 1},  // 6: DBM_ANTNOISE
//     {2, 2},  // 7: LOCK_QUALITY
//     {2, 2},  // 8: TX_ATTENUATION
//     {2, 2},  // 9: DB_TX_ATTENUATION
//     {1, 1},  // 10: DBM_TX_POWER
//     {1, 1},  // 11: ANTENNA
//     {1, 1},  // 12: DB_ANTSIGNAL
//     {1, 1},  // 13: DB_ANTNOISE
        //나중에 계속 추가...
// };

// SSID 추출
void parseSSID(const uint8_t* tagStart, int tagLen, string& ssidOut)
{
    int pos = 0;
    while (pos + 2 <= tagLen) { //tag number + tag length
        const taggedParam* tag = reinterpret_cast<const taggedParam*>(tagStart + pos);
        if (pos + 2 + tag->length_ > tagLen) break;

        if (tag->number_ == taggedParam::SSID) {
            if (tag->length_ > 0)
                ssidOut.assign(reinterpret_cast<const char*>(tag->value()),tag->length_);
        }
        pos += 2 + tag->length_;
    }

}

// pcap 열기
pcap_t* openHandle(const char* iface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(iface, BUFSIZ, 1, 1, errbuf);
    return handle;
}

// 비콘 처리
void processBeacon(const uint8_t* pkt, int len, uint16_t rtLen) {
    int minLen = rtLen + static_cast<int>(sizeof(IEEE80211Header)) + static_cast<int>(sizeof(fixedParam));
    if (len < minLen) return;

    // BSSID 추출
    const IEEE80211Header* wifiName = reinterpret_cast<const IEEE80211Header*>(pkt + rtLen);
    Mac bssid = wifiName->bssid();

    // 태그 파라미터 위치 계산
    const uint8_t* tagStart = pkt + rtLen + sizeof(IEEE80211Header) + sizeof(fixedParam);
    int tagLen = len - rtLen - sizeof(IEEE80211Header) - sizeof(fixedParam);

    // SSID 파싱
    string ssid;
    parseSSID(tagStart, tagLen, ssid);

    // map 업데이트 (find 한 번만)
    map<Mac, ApInfo>::iterator it = apMap.find(bssid);
    if (it != apMap.end()) {
        it->second.beacons++;
    } else {
        ApInfo info;
        info.bssid = bssid;
        info.ssid = ssid;
        info.beacons = 1;
        apMap[bssid] = info;
    }
}

// 화면 출력
void display() {
    printf("\033[H\033[2J");
    printf(" %-18s  %8s  %s\n", "BSSID", "Beacons", "ESSID");

    for (std::map<Mac, ApInfo>::iterator it = apMap.begin();
         it != apMap.end(); ++it)
    {
        printf(" ");
        it->first.printMac();
        printf("  %8u  %s\n", it->second.beacons, it->second.ssid.c_str());
    }
}

// 패킷 수신 
void processPacket(const uint8_t* pkt, int len) {
    if (len < static_cast<int>(sizeof(RadiotapHeader))) return;

    const RadiotapHeader* rt =
        reinterpret_cast<const RadiotapHeader*>(pkt);

    uint16_t rtLen = rt->rtLen();

    if (len < rtLen + static_cast<int>(sizeof(IEEE80211))) return;

    const IEEE80211* ieee80211 =
        reinterpret_cast<const IEEE80211*>(pkt + rtLen);

    if (!ieee80211->isBeacon()) return;

    processBeacon(pkt, len, rtLen);
    display();
}

void captureLoop(pcap_t* handle) {
    struct pcap_pkthdr* header;
    const uint8_t* pkt;

    while (true) {
        int res = pcap_next_ex(handle, &header, &pkt);
        if (res == 0) continue;
        if (res < 0) {
            fprintf(stderr, "pcap_next_ex: %s\n", pcap_geterr(handle));
            break;
        }
        processPacket(pkt, header->caplen);
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <monitor-interface>\n", argv[0]);
        return 1;
    }

    pcap_t* handle = openHandle(argv[1]);
    captureLoop(handle);
    pcap_close(handle);
    return 0;
}