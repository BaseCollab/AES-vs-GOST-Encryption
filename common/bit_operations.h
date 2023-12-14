#ifndef ENCRYPTION_COMMON_BIT_OPERATIONS_H
#define ENCRYPTION_COMMON_BIT_OPERATIONS_H

#include <cstdint>
#include <cstring>

namespace bitops {

// clang-format off
inline void XorArray(uint8_t *out, const uint8_t *lhs, const uint8_t *rhs, const size_t size)
{
    static constexpr size_t kShift  = 3;
    static constexpr size_t kMask32 = 0x04;
    static constexpr size_t kMask16 = 0x02;
    static constexpr size_t kMask8  = 0x01;

    size_t nIters = size >> kShift;

    uint64_t left  = 0;
    uint64_t right = 0;

    for (size_t i = 0; i < nIters; i++) {
        std::memcpy(&left,  lhs, sizeof(uint64_t));
        std::memcpy(&right, rhs, sizeof(uint64_t));

        left = left ^ right;

        std::memcpy(out, &left, sizeof(uint64_t));

        lhs += sizeof(uint64_t);
        rhs += sizeof(uint64_t);
        out += sizeof(uint64_t);
    }

    if (size & kMask32) {
        std::memcpy(&left,  lhs, sizeof(uint32_t));
        std::memcpy(&right, rhs, sizeof(uint32_t));

        left = left ^ right;

        std::memcpy(out, &left, sizeof(uint32_t));

        lhs += sizeof(uint32_t);
        rhs += sizeof(uint32_t);
        out += sizeof(uint32_t);
    }

    if (size & kMask16) {
        std::memcpy(&left,  lhs, sizeof(uint16_t));
        std::memcpy(&right, rhs, sizeof(uint16_t));

        left = left ^ right;

        std::memcpy(out, &left, sizeof(uint16_t));

        lhs += sizeof(uint16_t);
        rhs += sizeof(uint16_t);
        out += sizeof(uint16_t);
    }

    if (size & kMask8) {
        std::memcpy(&left,  lhs, sizeof(uint8_t));
        std::memcpy(&right, rhs, sizeof(uint8_t));

        left = left ^ right;

        std::memcpy(out, &left, sizeof(uint8_t));
    }
}
// clang-format on

inline uint64_t GetQWord(uint32_t a, uint32_t b)
{
    return (static_cast<uint64_t>(a) << 32) | static_cast<uint64_t>(b);
}

} // namespace bitops

#endif // ENCRYPTION_COMMON_BIT_OPERATIONS_H
