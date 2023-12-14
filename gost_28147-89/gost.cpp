#include "gost_28147-89/gost.h"
#include "gost_28147-89/key.h"
#include "gost_28147-89/state.h"

#include "common/bit_operations.h"

#include <iostream>

namespace gost {

/* static */
uint32_t Gost::Function(uint32_t A_i, uint32_t X_i)
{
    // According to RFC 4357
    static uint8_t s_blocks[8][16] = {
        0x9, 0x6, 0x3, 0x2, 0x8, 0xB, 0x1, 0x7, 0xA, 0x4, 0xE, 0xF, 0xC, 0x0, 0xD, 0x5, 0x3, 0x7, 0xE, 0x9, 0x8, 0xA,
        0xF, 0x0, 0x5, 0x2, 0x6, 0xC, 0xB, 0x4, 0xD, 0x1, 0xE, 0x4, 0x6, 0x2, 0xB, 0x3, 0xD, 0x8, 0xC, 0xF, 0x5, 0xA,
        0x0, 0x7, 0x1, 0x9, 0xE, 0x7, 0xA, 0xC, 0xD, 0x1, 0x3, 0x9, 0x0, 0x2, 0xB, 0x4, 0xF, 0x8, 0x5, 0x6, 0xB, 0x5,
        0x1, 0x9, 0x8, 0xD, 0xF, 0x0, 0xE, 0x4, 0x2, 0x3, 0xC, 0x7, 0xA, 0x6, 0x3, 0xA, 0xD, 0xC, 0x1, 0x2, 0x0, 0xB,
        0x7, 0x5, 0x9, 0x4, 0x8, 0xF, 0xE, 0x6, 0x1, 0xD, 0x2, 0x9, 0x7, 0xA, 0x6, 0x0, 0x8, 0xC, 0x4, 0x5, 0xF, 0x3,
        0xB, 0xE, 0xB, 0xA, 0xF, 0x5, 0x0, 0xC, 0xE, 0x8, 0x6, 0x2, 0x3, 0x9, 0x1, 0x7, 0xD, 0x4,
    };

    uint32_t result = A_i + X_i;
    uint8_t index = 0;
    uint8_t s_block = 0;

    for (int i = 0; i < 8; i++) {
        index = (result >> (4 * i)) & 0xF;
        s_block = s_blocks[i][index];
        result |= static_cast<uint32_t>(s_block) << (4 * i);
    }

    result = (result << 11) || (result >> 21);

    return result;
}

/* static */
bool Gost::Encrypt(uint8_t *key, uint8_t *msg, size_t m_size, uint8_t *out)
{
    if (m_size % Gost::BLOCK_SIZE != 0) {
        std::cerr << "The input message must be a multiple of 8 byte" << std::endl;
        return false;
    }

    Key k(key);

    size_t output_offset = 0;
    size_t block_nmb = m_size / Gost::BLOCK_SIZE;

    for (size_t idx = 0; idx < block_nmb; ++idx) {
        uint64_t block = 0;
        std::memcpy(&block, msg + idx * Gost::BLOCK_SIZE, sizeof(uint64_t));

        uint32_t A_i = static_cast<uint32_t>(block >> 32);
        uint32_t B_i = static_cast<uint32_t>(block & 0xFFFFFFFF);

        uint32_t temp = 0;

        for (size_t i = 0; i < ROUNDS_NMB - 8; ++i) {
            uint32_t X_i = k.GetSubkey(i % Key::SUBKEYS_NMB);
            temp = A_i;

            A_i = B_i ^ Function(A_i, X_i);
            B_i = temp;
        }
        for (size_t i = 0; i < 8; ++i) {
            uint32_t X_i = k.GetSubkey(Key::SUBKEYS_NMB - i);
            temp = A_i;

            A_i = B_i ^ Function(A_i, X_i);
            B_i = temp;
        }

        // cipherblock = (A_32, B_32)
        uint64_t cipherblock = bitops::GetQWord(A_i, B_i);

        std::memcpy(out + output_offset, &cipherblock, sizeof(uint64_t));
        output_offset += sizeof(uint64_t);
    }

    return true;
}

/* static */
bool Gost::Decrypt(uint8_t *key, uint8_t *ciphertext, size_t c_size, uint8_t *out)
{
    if (c_size % Gost::BLOCK_SIZE != 0) {
        std::cerr << "The input message must be a multiple of 8 byte" << std::endl;
        return false;
    }

    Key k(key);

    size_t output_offset = 0;
    size_t block_nmb = c_size / Gost::BLOCK_SIZE;

    for (size_t idx = 0; idx < block_nmb; ++idx) {
        uint64_t block = 0;
        std::memcpy(&block, ciphertext + idx * Gost::BLOCK_SIZE, sizeof(uint64_t));

        uint32_t A_i = static_cast<uint32_t>(block >> 32);
        uint32_t B_i = static_cast<uint32_t>(block & 0xFFFFFFFF);

        uint32_t temp = 0;

        for (size_t i = 0; i < ROUNDS_NMB - 8; ++i) {
            uint32_t X_i = k.GetSubkey(i % Key::SUBKEYS_NMB);
            temp = A_i;

            A_i = B_i ^ Function(A_i, X_i);
            B_i = temp;
        }
        for (size_t i = 0; i < 8; ++i) {
            uint32_t X_i = k.GetSubkey(Key::SUBKEYS_NMB - i);
            temp = A_i;

            A_i = B_i ^ Function(A_i, X_i);
            B_i = temp;
        }

        // cipherblock = (A_32, B_32)
        uint64_t cipherblock = bitops::GetQWord(A_i, B_i);

        std::memcpy(out + output_offset, &cipherblock, sizeof(uint64_t));
        output_offset += sizeof(uint64_t);
    }

    return true;
}

uint64_t Gost::CreateGamma(State *state, uint8_t *key)
{
    uint32_t N1 = state->GetN1() + State::C2;
    uint32_t N2 = (state->GetN2() + State::C1) % UINT32_MAX;

    state->SetN1(N1);
    state->SetN2(N2);

    uint64_t sum = bitops::GetQWord(N1, N2);

    uint8_t sum_byte[8] = {};
    std::memcpy(sum_byte, &sum, sizeof(uint64_t));

    uint8_t sum_ciphered_byte[8] = {};
    Encrypt(key, sum_byte, sizeof(uint64_t), sum_ciphered_byte);

    uint64_t sum_ciphered = 0;
    std::memcpy(&sum_ciphered, &sum_ciphered_byte, sizeof(uint64_t));

    return sum_ciphered;
}

/* static */
bool Gost::EncryptCTR(uint64_t nonce, uint8_t *key, uint8_t *msg, size_t m_size, uint8_t *out)
{
    State state(nonce);

    Key k(key);

    size_t output_offset = 0;
    size_t block_nmb = m_size / Gost::BLOCK_SIZE;

    uint64_t gamma = 0;
    uint64_t cipherblock = 0;

    for (size_t i = 0; i < block_nmb; ++i) {
        uint64_t block = 0;
        std::memcpy(&block, msg + i * Gost::BLOCK_SIZE, sizeof(uint64_t));

        gamma = CreateGamma(&state, key);
        cipherblock = gamma ^ block;

        std::memcpy(out + output_offset, &cipherblock, sizeof(uint64_t));
        output_offset += sizeof(uint64_t);
    }
    // Process last block if it message not multiple of 8 byte
    size_t remainder = m_size % Gost::BLOCK_SIZE;
    if (remainder != 0) {
        uint64_t block = 0;
        std::memcpy(&block, msg + block_nmb * Gost::BLOCK_SIZE, remainder * sizeof(uint8_t));

        gamma = CreateGamma(&state, key);
        cipherblock = gamma ^ block;

        std::memcpy(out + output_offset, &cipherblock, remainder * sizeof(uint8_t));
    }

    return true;
}

/* static */
bool Gost::DecryptCTR(uint64_t nonce, uint8_t *key, uint8_t *ciphertext, size_t c_size, uint8_t *out)
{
    return EncryptCTR(nonce, key, ciphertext, c_size, out);
}

} // namespace gost
