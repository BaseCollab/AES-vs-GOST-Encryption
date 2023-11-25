#include "aes/aes.h"
#include "common/defines.h"

#include <cstdio>
#include <cstdint>
#include <cstring>

AES::AES(const AES::KeyLength key_length)
{
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
    AES::State state;

    for (size_t i = 0; i < sizeof(word_t); i++)
        for (size_t j = 0; j < AES::NB; j++)
            state[i][j] = in[i + sizeof(word_t) * j];

    AddRoundKey(state, round_keys);

    for (size_t round = 1; round < n_rounds_; round++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, round_keys + round * sizeof(word_t) * AES::NB);
    }

    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, round_keys + n_rounds_ * sizeof(word_t) * AES::NB);

    for (size_t i = 0; i < sizeof(word_t); i++)
        for (size_t j = 0; j < AES::NB; j++)
            out[i + sizeof(word_t) * j] = state[i][j];
}

void AES::DecryptBlock(const uint8_t in[], uint8_t out[], const uint8_t *round_keys)
{
    AES::State state;

    for (size_t i = 0; i < sizeof(word_t); i++)
        for (size_t j = 0; j < AES::NB; j++)
            state[i][j] = in[i + sizeof(word_t) * j];

    AddRoundKey(state, round_keys + n_rounds_ * sizeof(word_t) * AES::NB);

    for (size_t round = n_rounds_ - 1; round > 0; round--) {
        SubBytesInv(state);
        ShiftRowsInv(state);
        AddRoundKey(state, round_keys + round * sizeof(word_t) * AES::NB);
        MixColumnsInv(state);
    }

    SubBytesInv(state);
    ShiftRowsInv(state);
    AddRoundKey(state, round_keys);

    for (size_t i = 0; i < sizeof(word_t); i++)
        for (size_t j = 0; j < AES::NB; j++)
            out[i + sizeof(word_t) * j] = state[i][j];
}
