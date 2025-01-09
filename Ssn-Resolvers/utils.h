#pragma once
#ifndef UTILS_H
#define UTILS_H

#include <cstdint>

inline uint64_t djb2(const uint8_t* str) {
    uint64_t dwHash = 0x7734773477347734;
    int c;
    while ((c = *str++)) {
        dwHash = ((dwHash << 5) + dwHash) + c;
    }
    return dwHash;
}

#endif 
