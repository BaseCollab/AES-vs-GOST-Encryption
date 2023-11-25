#ifndef BIT_OPERATIONS
#define BIT_OPERATIONS

#include <cstdint>
#include <cstring>

namespace BitOps
{

inline void XorArray(uint8_t* out, const uint8_t* lhs, const uint8_t* rhs, const size_t size)
{
    static constexpr size_t kShift  = 3;
    static constexpr size_t kMask32 = 0x04;
    static constexpr size_t kMask16 = 0x02;
    static constexpr size_t kMask8  = 0x01;

    size_t nIters = size >> kShift;

    uint64_t left  = 0;
    uint64_t right = 0;

    for (size_t i = 0; i < nIters; i++)
    {
        memcpy(&left,  lhs, sizeof(uint64_t));
        memcpy(&right, rhs, sizeof(uint64_t));

        left = left ^ right;

        memcpy(out, &left, sizeof(uint64_t));

        lhs += sizeof(uint64_t);
        rhs += sizeof(uint64_t);
        out += sizeof(uint64_t);
    }

    if (size & kMask32)
    {
        memcpy(&left,  lhs, sizeof(uint32_t));
        memcpy(&right, rhs, sizeof(uint32_t));

        left = left ^ right;

        memcpy(out, &left, sizeof(uint32_t));

        lhs += sizeof(uint32_t);
        rhs += sizeof(uint32_t);
        out += sizeof(uint32_t);
    }

    if (size & kMask16)
    {
        memcpy(&left,  lhs, sizeof(uint16_t));
        memcpy(&right, rhs, sizeof(uint16_t));

        left = left ^ right;

        memcpy(out, &left, sizeof(uint16_t));

        lhs += sizeof(uint16_t);
        rhs += sizeof(uint16_t);
        out += sizeof(uint16_t);
    }

    if (size & kMask8)
    {
        memcpy(&left,  lhs, sizeof(uint8_t));
        memcpy(&right, rhs, sizeof(uint8_t));

        left = left ^ right;

        memcpy(out, &left, sizeof(uint8_t));

    }
}


}

#endif // BIT_OPERATIONS
