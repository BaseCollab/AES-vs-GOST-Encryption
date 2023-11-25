#ifndef CHACHA20_H
#define CHACHA20_H

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <gtest/gtest.h>

#include "common/intrinsics.h"
#include "common/bit_operations.h"

namespace ChaCha20
{

struct Key
{
    static constexpr size_t kKeyBitSize   = 256;
    static constexpr size_t kKeyByteSize  = kKeyBitSize >> 3;
    static constexpr size_t kKeyStateSize = kKeyByteSize / sizeof(uint32_t);

    template <typename ... T>
    explicit Key(T... ts) :
        key{static_cast<uint8_t>(ts)...}
    {}

    union
    {
        uint8_t key[kKeyByteSize];
        uint32_t state[kKeyStateSize];
    };
};

struct Nonce
{
    static constexpr size_t kNonceBitSize   = 96;
    static constexpr size_t kNonceByteSize  = kNonceBitSize >> 3;
    static constexpr size_t kNonceStateSize = kNonceByteSize / sizeof(uint32_t);

    template <typename ... T>
    explicit Nonce(T... ts) :
        nonce{static_cast<uint8_t>(ts)...}
    {}

    union
    {
        uint8_t nonce[kNonceByteSize];
        uint32_t state[kNonceStateSize];
    };
};

class Cipher
{
public:
    static constexpr size_t kBlockSize = 64;

    static void Encrypt(const Key& key, const uint32_t counter, const Nonce& nonce,
                        const uint8_t* plaintext, uint8_t* ciphertext, const size_t len);

    static void Decrypt(const Key& key, const uint32_t counter, const Nonce& nonce,
                        const uint8_t* ciphertext, uint8_t* plaintext, const size_t len);

private:
    FRIEND_TEST(ChaCha20Test, QuaterRound);
    FRIEND_TEST(ChaCha20Test, StateInit);
    FRIEND_TEST(ChaCha20Test, BlockInner);
    FRIEND_TEST(ChaCha20Test, Block);

    static constexpr size_t kBlockSizeShift  = 6;
    static constexpr size_t kBlockSizeMask   = 0x3F;

    static constexpr size_t kRounds          = 20;
    static constexpr size_t kBlockInnerIters = kRounds / 2;

    static constexpr size_t kNumConstant = 4;
    static constexpr uint32_t kConstant[kNumConstant] =
        {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};

    struct State
    {
        static constexpr size_t kStateSize = 16;

        inline State() :
            state{}
        {}

        inline State(const Key& key, const uint32_t counter, const Nonce& nonce)
        {
            Init(key, counter, nonce);
        }

        State& operator+=(const State& rhs)
        {
            for (size_t i = 0; i < kStateSize; i++)
                state[i] += rhs.state[i];

            return *this;
        }

        inline void Init(const Key& initKey, const uint32_t counter, const Nonce& initNonce)
        {
            memcpy(input.constant, kConstant, sizeof(kConstant));

            input.key          = initKey;
            input.blockCounter = counter;
            input.nonce        = initNonce;
        }

        union
        {
            struct
            {
                uint32_t constant[kNumConstant];
                Key      key;
                uint32_t blockCounter;
                Nonce    nonce;

            } input;

            uint8_t  buffer[kBlockSize];
            uint32_t state[kStateSize];
        };
    };

    static_assert(sizeof(State) == State::kStateSize * sizeof(uint32_t));

    static void Block(const Key& key, const uint32_t counter, const Nonce& nonce, State* out);

    static void InnerBlock(State* state);

    static void QuarterRound(uint32_t* a, uint32_t* b, uint32_t* c, uint32_t* d);

}; // class Cipher

} // namespace Chacha20

#endif // CHACHA20_H
