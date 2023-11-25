#include "chacha20.h"

namespace ChaCha20
{

void Cipher::Encrypt(const Key& key, const uint32_t counter, const Nonce& nonce,
                     const uint8_t* plaintext, uint8_t* ciphertext, const size_t len)
{
    State keyStream{};

    size_t j = 0;

    for (j = 0; j < (len >> kBlockSizeShift); j++)
    {
        Block(key, counter + j, nonce, &keyStream);
        BitOps::XorArray(ciphertext, plaintext, keyStream.buffer, kBlockSize);

        ciphertext += kBlockSize;
        plaintext  += kBlockSize;
    }

    if (len & kBlockSizeMask)
    {
        Block(key, counter + j, nonce, &keyStream);
        BitOps::XorArray(ciphertext, plaintext, keyStream.buffer, len & kBlockSizeMask);
    }
}

void Cipher::Decrypt(const Key& key, const uint32_t counter, const Nonce& nonce,
                     const uint8_t* ciphertext, uint8_t* plaintext, const size_t len)
{
    Encrypt(key, counter, nonce, ciphertext, plaintext, len);
}

void Cipher::Block(const Key& key, const uint32_t counter, const Nonce& nonce, State* state)
{
    state->Init(key, counter, nonce);
    State work = *state;

    for (size_t i = 0; i < Cipher::kBlockInnerIters; i++)
        InnerBlock(&work);

    *state += work;
}

#define QROUND_(a, b, c, d) \
        QuarterRound(state->state + a, state->state + b, state->state + c, state->state + d)

void Cipher::InnerBlock(State* state)
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

void Cipher::QuarterRound(uint32_t* a, uint32_t* b, uint32_t* c, uint32_t* d)
{
    *a += *b; *d ^= *a; ROTL_(*d, 16);
    *c += *d; *b ^= *c; ROTL_(*b, 12);
    *a += *b; *d ^= *a; ROTL_(*d,  8);
    *c += *d; *b ^= *c; ROTL_(*b,  7);
}

#undef ROTL_

} // namespace Chacha20
