#pragma once

#include <cstdint>
#include <cstring>
#include <cstdio>
#include "mac.h"

#pragma pack(push, 1)

struct Dot11Hdr {
    uint8_t subtype_;
    uint8_t verType_;
    uint16_t durationId_;
    Mac addr1_;
    Mac addr2_;
    Mac addr3_;
    uint16_t seqCtrl_;

    bool isBeacon() const { return (subtype_ == 0x80) && (verType_ == 0x00); }
    bool isData() const { return (verType_ & 0x0C) == 0x08; }
};
typedef Dot11Hdr* PDot11Hdr;

struct BeaconHdr : public Dot11Hdr {
    Mac dest() const { return addr1_; }
    Mac src() const { return addr2_; }
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
    };

    struct EcsaTag : Tag {
        uint8_t switchMode;
        uint8_t newOpClass;
        uint8_t newChannel;
        uint8_t switchCount;
    };

    Tag* firstTag() const {
        return (Tag*)((uint8_t*)this + sizeof(Dot11Hdr) + sizeof(Fix));
    }

};
typedef BeaconHdr* PBeaconHdr;

#pragma pack(pop)