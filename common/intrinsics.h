#ifndef INTRINSICS_H
#define INTRINSICS_H

#include <cstdint>

#if defined(__x86_64__)

#include "x86intrin.h"

inline uint32_t rotl(const uint32_t x, const uint8_t n)
{
    return _rotl(x, n);
}

#else // defined(__x86_64__)

inline uint32_t rotl(const uint32_t x, const uint32_t n)
{
    static constexpr uint32_t mask = UINT32_WIDTH - 1;

    uint32_t shift  = ( n) & mask;
    uint32_t rshift = (-n) & mask;

    return (x >> shift) | (n << rshift);
}

#endif // defined(__x86_64__)

#endif // INTRINSICS_H
