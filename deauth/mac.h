#pragma once

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <string>

struct Mac {
    uint8_t mac_[6];

    Mac() { memset(mac_, 0, 6); }

    Mac(const uint8_t* p) { memcpy(mac_, p, 6); }  // int8_t → uint8_t

    Mac(const Mac& r) { memcpy(mac_, r.mac_, 6); }  // const 추가 + 정의

    // 문자열로부터 생성 — "00:11:22:33:44:55"
    Mac(const char* s) {
        unsigned int b[6];
        if (sscanf(s, "%02x:%02x:%02x:%02x:%02x:%02x",
                   &b[0],&b[1],&b[2],&b[3],&b[4],&b[5]) == 6)
            for (int i = 0; i < 6; i++) mac_[i] = (uint8_t)b[i];
        else
            memset(mac_, 0, 6);
    }

    bool operator<(const Mac& r) const {
        return memcmp(mac_, r.mac_, 6) < 0;
    }

    bool operator==(const Mac& r) const {
        return memcmp(mac_, r.mac_, 6) == 0;
    }

    // 노트: printf 대신 string 변환 방식으로 교체
    std::string toString() const {
        char buf[18];
        snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                 mac_[0], mac_[1], mac_[2], mac_[3], mac_[4], mac_[5]);
        return std::string(buf);
    }

    operator std::string() const { return toString(); }
};