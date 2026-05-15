#pragma once

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <string>

struct Mac {
    uint8_t mac_[6];

    Mac();
    Mac(const uint8_t* p);
    Mac(const Mac& r);
    Mac(const char* s);

    bool operator<(const Mac& r) const;
    bool operator==(const Mac& r) const;

    std::string toString() const;
    operator std::string() const;
};
typedef Mac* PMac;