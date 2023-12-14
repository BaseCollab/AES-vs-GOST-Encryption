#ifndef ENCRYPTION_CHACHA20_CHACHA20_H
#define ENCRYPTION_CHACHA20_CHACHA20_H

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <gtest/gtest.h>

#include "common/intrinsics.h"
#include "common/bit_operations.h"

// clang-format off
namespace chacha20 {

struct Key {
    static constexpr size_t KEY_BIT_SIZE   = 256;
    static constexpr size_t KEY_BYTE_SIZE  = KEY_BIT_SIZE >> 3;
    static constexpr size_t KEY_STATE_SIZE = KEY_BYTE_SIZE / sizeof(uint32_t);

    template <typename... T>
    explicit Key(T... ts) : state {}
    {
        uint8_t key[KEY_BYTE_SIZE] = {static_cast<uint8_t>(ts)...};

        std::memcpy(state, key, sizeof(key));
    }

    explicit Key(uint8_t array[KEY_BYTE_SIZE]) : state {}
    {
        std::memcpy(state, array, KEY_BYTE_SIZE);
    }

    uint32_t state[KEY_STATE_SIZE];
};

struct Nonce {
    static constexpr size_t NONCE_BIT_SIZE   = 96;
    static constexpr size_t NONCE_BYTE_SIZE  = NONCE_BIT_SIZE >> 3;
    static constexpr size_t NONCE_STATE_SIZE = NONCE_BYTE_SIZE / sizeof(uint32_t);

    template <typename... T>
    explicit Nonce(T... ts) : state {}
    {
        uint8_t nonce[NONCE_BYTE_SIZE] = {static_cast<uint8_t>(ts)...};

        std::memcpy(state, nonce, sizeof(nonce));
    }

    explicit Nonce(uint8_t array[NONCE_BYTE_SIZE]) : state {}
    {
        std::memcpy(state, array, NONCE_BYTE_SIZE);
    }

    uint32_t state[NONCE_STATE_SIZE];
};

class Cipher {
public:
    static constexpr size_t BLOCK_SIZE = 64;

    static void Encrypt(const Key &key, const uint32_t counter, const Nonce &nonce,
                        const uint8_t *plaintext, uint8_t *ciphertext, const size_t len);

    static void Decrypt(const Key &key, const uint32_t counter, const Nonce &nonce,
                        const uint8_t *ciphertext, uint8_t *plaintext, const size_t len);

private:
    FRIEND_TEST(ChaCha20Test, QuaterRound);
    FRIEND_TEST(ChaCha20Test, StateInit);
    FRIEND_TEST(ChaCha20Test, ProcessBlockInner);
    FRIEND_TEST(ChaCha20Test, ProcessBlock);

    static constexpr size_t BLOCK_SIZE_SHIFT = 6;
    static constexpr size_t BLOCK_SIZE_MASK  = 0x3F;

    static constexpr size_t ROUNDS = 20;
    static constexpr size_t BLOCK_INNER_ITERS = ROUNDS / 2;

    static constexpr size_t NUM_CONSTANT = 4;
    static constexpr uint32_t CONSTANT[NUM_CONSTANT] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};

    struct State {
        static constexpr size_t STATE_SIZE = 16;

        inline State() : state {} {}

        inline State(const Key &key, const uint32_t counter, const Nonce &nonce)
        {
            Init(key, counter, nonce);
        }

        State &operator+=(const State &rhs)
        {
            for (size_t i = 0; i < STATE_SIZE; i++)
                state[i] += rhs.state[i];

            return *this;
        }

        inline void Init(const Key &key, const uint32_t counter, const Nonce &nonce)
        {
            static constexpr size_t CONSTANT_OFFSET = 0;
            static constexpr size_t KEY_OFFSET      = 16;
            static constexpr size_t COUNTER_OFFSET  = 48;
            static constexpr size_t NONCE_OFFSET    = 52;

            uint8_t *base = reinterpret_cast<uint8_t *>(state);

            std::memcpy(base + CONSTANT_OFFSET, CONSTANT,    sizeof(CONSTANT));
            std::memcpy(base + KEY_OFFSET,      key.state,   Key::KEY_BYTE_SIZE);
            std::memcpy(base + COUNTER_OFFSET,  &counter,    sizeof(uint32_t));
            std::memcpy(base + NONCE_OFFSET,    nonce.state, Nonce::NONCE_BYTE_SIZE);
        }

        uint32_t state[STATE_SIZE];
    };

    static_assert(sizeof(State) == State::STATE_SIZE * sizeof(uint32_t));

    static void ProcessBlock(const Key &key, const uint32_t counter, const Nonce &nonce, State *out);

    static void ProcessInnerBlock(State *state);

    static void QuarterRound(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d);

}; // class Cipher

} // namespace chacha20
// clang-format on

#endif // ENCRYPTION_CHACHA20_CHACHA20_H
