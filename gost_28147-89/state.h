#ifndef ENCRYPTION_GOST_STATE_H
#define ENCRYPTION_GOST_STATE_H

#include <cstdint>
#include <cstddef>
#include <cstring>

namespace gost {

class State {
public:
    static constexpr size_t C2 = 0x01010101;
    static constexpr size_t C1 = 0x01010104;

    explicit State(uint64_t nonce) : nonce_(nonce)
    {
        N1_ = static_cast<uint32_t>(nonce_ >> 32);
        N2_ = static_cast<uint32_t>(nonce_ & 0xFFFFFFFF);
    }

    ~State() = default;

    uint32_t GetN1() const
    {
        return N1_;
    }

    uint32_t GetN2() const
    {
        return N2_;
    }

    void SetN1(uint32_t N1)
    {
        N1_ = N1;
    }

    void SetN2(uint32_t N2)
    {
        N2_ = N2;
    }

private:
    uint64_t nonce_ {0};
    uint32_t N1_ {0};
    uint32_t N2_ {0};
};

} // namespace gost

#endif // ENCRYPTION_GOST_STATE_H
