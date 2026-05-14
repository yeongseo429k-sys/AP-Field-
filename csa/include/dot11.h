#pragma once

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <pcap.h>
#include "mac.h"

#pragma pack(push, 1)

struct Dot11Hdr {
    uint8_t  subtype_;
    uint8_t  ver_type_;
    uint16_t duration_id_;
    Mac      addr1_;
    Mac      addr2_;
    Mac      addr3_;
    uint16_t seq_control_;

    bool is_beacon() const { return (subtype_ == 0x80) && (ver_type_ == 0x00); }
    bool is_data() const   { return (ver_type_ & 0x0C) == 0x08; }
};
typedef Dot11Hdr* PDot11Hdr;

struct BeaconHdr : public Dot11Hdr {
    Mac dest()  const { return addr1_; }
    Mac src()   const { return addr2_; }
    Mac bssid() const { return addr3_; }

    struct Fix {
        uint64_t timestamp;
        uint16_t beaconInterval;
        uint16_t capabilityInfo;
    } fix_;

    struct Tag {
        uint8_t number;
        uint8_t length;

        Tag* next() const {
            return (Tag*)((uint8_t*)this + sizeof(Tag) + length);
        }
    };

    struct CsaTag : Tag {
        uint8_t channelSwitchMode;
        uint8_t newChannel;
        uint8_t channelSwitchCount;
    } csaTag_;

    Tag* first_tag() const {
        return (Tag*)((uint8_t*)this + sizeof(Dot11Hdr) + sizeof(Fix));
    }
};
typedef BeaconHdr* PBeaconHdr;

#pragma pack(pop)

void initCsaTag(BeaconHdr::CsaTag* tag);
void setAddr1(uint8_t* packet, int radiotapLen, const Mac& addr1);
bool captureBeacon(pcap_t* handle, const Mac& apMac,
                   int radiotapLen, uint8_t* buf, int* len);
int  buildCsaPacket(const uint8_t* captured, int capLen,
                   int radiotapLen, bool fcs,
                   uint8_t* outBuf, int outBufSize);