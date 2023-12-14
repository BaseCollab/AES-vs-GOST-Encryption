#include "chacha20.h"

// clang-format off
namespace chacha20 {

void Cipher::Encrypt(const Key &key, const uint32_t counter, const Nonce &nonce,
                     const uint8_t *plaintext, uint8_t *ciphertext, const size_t len)
{
    State keyStream {};

    size_t j = 0;

    uint8_t *state = reinterpret_cast<uint8_t *>(keyStream.state);

    for (j = 0; j < (len >> BLOCK_SIZE_SHIFT); j++) {
        ProcessBlock(key, counter + j, nonce, &keyStream);
        BitOps::XorArray(ciphertext, plaintext, state, BLOCK_SIZE);

        ciphertext += BLOCK_SIZE;
        plaintext  += BLOCK_SIZE;
    }

    if (len & BLOCK_SIZE_MASK) {
        ProcessBlock(key, counter + j, nonce, &keyStream);
        BitOps::XorArray(ciphertext, plaintext, state, len & BLOCK_SIZE_MASK);
    }
}

void Cipher::Decrypt(const Key &key, const uint32_t counter, const Nonce &nonce,
                     const uint8_t *ciphertext, uint8_t *plaintext, const size_t len)
{
    Encrypt(key, counter, nonce, ciphertext, plaintext, len);
}

void Cipher::ProcessBlock(const Key &key, const uint32_t counter, const Nonce &nonce, State *state)
{
    state->Init(key, counter, nonce);
    State work = *state;

    for (size_t i = 0; i < Cipher::BLOCK_INNER_ITERS; i++)
        ProcessInnerBlock(&work);

    *state += work;
}

#define QROUND_(a, b, c, d) QuarterRound(state->state + a, state->state + b, state->state + c, state->state + d)

void Cipher::ProcessInnerBlock(State *state)
{
    QROUND_(0, 4,  8, 12);
    QROUND_(1, 5,  9, 13);
    QROUND_(2, 6, 10, 14);
    QROUND_(3, 7, 11, 15);
    QROUND_(0, 5, 10, 15);
    QROUND_(1, 6, 11, 12);
    QROUND_(2, 7,  8, 13);
    QROUND_(3, 4,  9, 14);
}

#undef QROUND_

#define ROTL_(x, shift) x = rotl(x, shift)

void Cipher::QuarterRound(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d)
{
    *a += *b; *d ^= *a; ROTL_(*d, 16);
    *c += *d; *b ^= *c; ROTL_(*b, 12);
    *a += *b; *d ^= *a; ROTL_(*d,  8);
    *c += *d; *b ^= *c; ROTL_(*b,  7);
}

#undef ROTL_

} // namespace chacha20
// clang-format on
