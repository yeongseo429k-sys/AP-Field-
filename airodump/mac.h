#pragma once

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <string>

struct Mac {
    uint8_t mac_[6];

    Mac() { memset(mac_, 0, 6); } //00:00:00:00:00:00 / 초기화 

    Mac(const uint8_t* p){ memcpy(mac_, p, 6);} //mac 주소 들어갈 수 있도록 그대로 복사 

    bool operator<(const Mac& r) const {
        return memcmp(mac_, r.mac_, 6) < 0;
    }

    bool operator==(const Mac& r) const {
        return memcmp(mac_, r.mac_, 6) == 0;
    }

    void printMac() const {
        printf("%02x:%02x:%02x:%02x:%02x:%02x", 
            mac_[0], mac_[1], mac_[2], mac_[3], mac_[4], mac_[5]);
    }

};