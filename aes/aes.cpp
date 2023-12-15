#include "aes/aes.h"
#include "common/defines.h"

#include <cstdio>
#include <cstdint>
#include <cstring>

#if defined(__arm__) || defined(__aarch32__) || defined(__arm64__) || defined(__aarch64__) || defined(_M_ARM)
    #if defined(__ARM_NEON) || defined(_MSC_VER)
        #include <arm_neon.h>
    #endif

    // GCC and LLVM Clang, but not Apple Clang
    #if defined(__GNUC__) && !defined(__apple_build_version__)
        #if defined(__ARM_ACLE) || defined(__ARM_FEATURE_CRYPTO)
            #include <arm_acle.h>
        #endif
    #endif
#endif

#if defined(__x86_64__) || defined(__amd64__) || (defined(_M_X64) || defined(_M_AMD64))
    #include <immintrin.h>
    #include <emmintrin.h>
#endif

AES::AES(const AES::KeyLength key_length, const HardwareSupport hw_sup)
{
    hw_support_ = hw_sup;

    switch (key_length) {
        case AES::KeyLength::AES_128:
            n_rounds_   = 10;
            key_length_ = 4;
            break;
        case AES::KeyLength::AES_192:
            n_rounds_   = 12;
            key_length_ = 6;
            break;
        case AES::KeyLength::AES_256:
            n_rounds_   = 14;
            key_length_ = 8;
            break;
    }
}

// AES-round procedures

void AES::KeyExpansion(const uint8_t key[], uint8_t key_expanded[])
{
    uint8_t tmp [sizeof(word_t)];
    uint8_t rcon[sizeof(word_t)];

    std::memcpy(key_expanded, key, sizeof(word_t) * key_length_);

    for (size_t i = sizeof(word_t) * key_length_; i < sizeof(word_t) * AES::NB * (n_rounds_ + 1); i += sizeof(word_t)) {
        std::memcpy(tmp, &(key_expanded[i - sizeof(word_t)]), sizeof(word_t));

        if ((i / sizeof(word_t)) % key_length_ == 0) {
            RotWord(tmp);
            SubWord(tmp);
            Rcon(rcon, (i / sizeof(word_t)) / key_length_);
            XorWords(tmp, rcon, tmp);
        } else if (key_length_ > 6 && (i / sizeof(word_t)) % key_length_ == 4) {
            SubWord(tmp);
        }

        for (size_t j = 0; j < sizeof(word_t); j++)
            key_expanded[i + j] = key_expanded[i + j - sizeof(word_t) * key_length_] ^ tmp[j];
    }
}

void AES::AddRoundKey(AES::State state, const uint8_t *round_key)
{
    for (size_t i = 0; i < sizeof(word_t); i++) {
        for (size_t j = 0; j < AES::NB; j++)
            state[i][j] = state[i][j] ^ round_key[i + sizeof(word_t) * j];
    }
}

// ShiftRows for encryption/decryption

void AES::ShiftRows(AES::State state)
{
    ShiftRow(state, 1, 1);
    ShiftRow(state, 2, 2);
    ShiftRow(state, 3, 3);
}

void AES::ShiftRowsInv(AES::State state)
{
    ShiftRow(state, 1, AES::NB - 1);
    ShiftRow(state, 2, AES::NB - 2);
    ShiftRow(state, 3, AES::NB - 3);
}

// SubBytes for encryption/decryption

void AES::SubBytes(AES::State state)
{
    for (size_t i = 0; i < sizeof(word_t); i++) {
        for (size_t j = 0; j < AES::NB; j++) {
            uint8_t tmp = state[i][j];
            state[i][j] = AES::SBOX[tmp >> 4][tmp & 0b00001111];
        }
    }
}

void AES::SubBytesInv(AES::State state)
{
    for (size_t i = 0; i < sizeof(word_t); i++) {
        for (size_t j = 0; j < AES::NB; j++) {
            uint8_t tmp = state[i][j];
            state[i][j] = AES::SBOX_INV[tmp >> 4][tmp & 0b00001111];
        }
    }
}

// MixColumns for encryption/decryption

void AES::MixColumns(AES::State state)
{
    AES::State state_tmp;

    for (size_t i = 0; i < sizeof(word_t); ++i)
        memset(state_tmp[i], 0, AES::NB);

    for (size_t i = 0; i < sizeof(word_t); ++i) {
        for (size_t k = 0; k < sizeof(word_t); ++k) {
            for (size_t j = 0; j < AES::NB; ++j) {
                if (CMDS[i][k] == 1)
                    state_tmp[i][j] ^= state[k][j];
                else
                    state_tmp[i][j] ^= GALOI_MUL_TABLE[CMDS[i][k]][state[k][j]];
            }
        }
    }

    for (size_t i = 0; i < sizeof(word_t); ++i)
        memcpy(state[i], state_tmp[i], AES::NB);
}

void AES::MixColumnsInv(AES::State state)
{
    AES::State state_tmp;

    for (size_t i = 0; i < sizeof(word_t); ++i)
        memset(state_tmp[i], 0, AES::NB);

    for (size_t i = 0; i < sizeof(word_t); ++i) {
        for (size_t k = 0; k < sizeof(word_t); ++k) {
            for (size_t j = 0; j < AES::NB; ++j)
                state_tmp[i][j] ^= GALOI_MUL_TABLE[CMDS_INV[i][k]][state[k][j]];
        }
    }

    for (size_t i = 0; i < sizeof(word_t); ++i)
        memcpy(state[i], state_tmp[i], AES::NB);
}

void AES::EncryptBlock(const uint8_t in[], uint8_t out[], const uint8_t *round_keys)
{
    switch (hw_support_)
    {
        case HardwareSupport::AES_CRYPTO_EXTENSION:
        {
#if defined(__arm__) || defined(__aarch32__) || defined(__arm64__) || defined(__aarch64__) || defined(_M_ARM)

            uint8x16_t state = vld1q_u8(in);

            for (size_t round = 0; round < (n_rounds_ - 1); ++round) {
                state = vaeseq_u8 (state, vld1q_u8(round_keys + round * sizeof(word_t) * AES::NB));
                state = vaesmcq_u8(state);
            }

            state = vaeseq_u8(state, vld1q_u8(round_keys + (n_rounds_ - 1) * sizeof(word_t) * AES::NB));
            state = veorq_u8 (state, vld1q_u8(round_keys +  n_rounds_      * sizeof(word_t) * AES::NB));

            vst1q_u8(out, state);
            break;

#elif defined(__x86_64__) || defined(__amd64__) || (defined(_M_X64) || defined(_M_AMD64))

            __m128i state = _mm_loadu_si128((__m128i *) in);
            state = _mm_xor_si128(state, _mm_loadu_si128((__m128i *) round_keys));

            for (size_t round = 1; round < n_rounds_; ++round) {
                state = _mm_aesenc_si128(state, _mm_loadu_si128((__m128i *)(round_keys + round * sizeof(word_t) * AES::NB)));
            }

            state = _mm_aesenclast_si128(state, _mm_loadu_si128((__m128i *)(round_keys + n_rounds_ * sizeof(word_t) * AES::NB)));
            _mm_storeu_si128((__m128i *) out, state);
            break;
#endif
        }

        case HardwareSupport::NONE:
        {
            AES::State state;

            for (size_t i = 0; i < sizeof(word_t); i++)
                for (size_t j = 0; j < AES::NB; j++)
                    state[i][j] = in[i + sizeof(word_t) * j];

            for (size_t round = 0; round < (n_rounds_ - 1); round++) {
                AddRoundKey(state, round_keys + round * sizeof(word_t) * AES::NB);
                SubBytes(state);
                ShiftRows(state);
                MixColumns(state);
            }

            AddRoundKey(state, round_keys + (n_rounds_ - 1) * sizeof(word_t) * AES::NB);
            SubBytes(state);
            ShiftRows(state);

            AddRoundKey(state, round_keys + n_rounds_ * sizeof(word_t) * AES::NB);

            for (size_t i = 0; i < sizeof(word_t); i++)
                for (size_t j = 0; j < AES::NB; j++)
                    out[i + sizeof(word_t) * j] = state[i][j];
        }
    }
}

void AES::DecryptBlock(const uint8_t in[], uint8_t out[], const uint8_t *round_keys)
{
    switch (hw_support_)
    {
        case HardwareSupport::AES_CRYPTO_EXTENSION:
        {
#if defined(__arm__) || defined(__aarch32__) || defined(__arm64__) || defined(__aarch64__) || defined(_M_ARM)

            uint8x16_t state = vld1q_u8(in);

            state = veorq_u8(state, vld1q_u8(round_keys + n_rounds_ * sizeof(word_t) * AES::NB));

            for (size_t round = n_rounds_ - 1; round > 0; --round)
            {
                state = vaesdq_u8  (state, vld1q_u8(round_keys + round * sizeof(word_t) * AES::NB));
                state = vaesimcq_u8(state);
            }

            state = vaesdq_u8(state, vld1q_u8(round_keys));

            vst1q_u8(out, state);
            break;

#elif defined(__x86_64__) || defined(__amd64__) || (defined(_M_X64) || defined(_M_AMD64))

            __m128i state = _mm_loadu_si128((__m128i *) in);
            state = _mm_xor_si128(state, _mm_loadu_si128((__m128i *)(round_keys + n_rounds_ * sizeof(word_t) * AES::NB)));

            for (size_t round = n_rounds_ - 1; round > 0; --round) {
                state = _mm_aesdec_si128(state, _mm_aesimc_si128(_mm_loadu_si128((__m128i *)(round_keys + round * sizeof(word_t) * AES::NB))));
            }

            state = _mm_aesdeclast_si128(state, _mm_loadu_si128((__m128i *) round_keys));
            _mm_storeu_si128((__m128i *) out, state);
            break;
#endif
        }

        case HardwareSupport::NONE:
        {
            AES::State state;

            for (size_t i = 0; i < sizeof(word_t); i++)
                for (size_t j = 0; j < AES::NB; j++)
                    state[i][j] = in[i + sizeof(word_t) * j];

            AddRoundKey(state, round_keys + n_rounds_ * sizeof(word_t) * AES::NB);

            for (size_t round = n_rounds_ - 1; round > 0; --round) {
                ShiftRowsInv(state);
                SubBytesInv(state);
                AddRoundKey(state, round_keys + round * sizeof(word_t) * AES::NB);
                MixColumnsInv(state);
            }

            ShiftRowsInv(state);
            SubBytesInv(state);
            AddRoundKey(state, round_keys);

            for (size_t i = 0; i < sizeof(word_t); i++)
                for (size_t j = 0; j < AES::NB; j++)
                    out[i + sizeof(word_t) * j] = state[i][j];
        }
    }
}
