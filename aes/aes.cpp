#include "aes/aes.h"
#include "common/defines.h"

#include <cstdio>
#include <cstdint>
#include <cstring>

namespace cryper
{

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

void AES::RotWord(uint8_t *word)
{
    uint8_t tmp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = tmp;
}

void AES::XorWords(uint8_t *word_in_1, uint8_t *word_in_2, uint8_t *word_out)
{
    for (size_t i = 0; i < sizeof(word_t); i++)
        word_out[i] = word_in_1[i] ^ word_in_2[i];
}

void AES::SubWord(uint8_t *word)
{
    for (size_t i = 0; i < sizeof(word_t); i++)
        word[i] = AES::SBOX[word[i] & 0b11110000][word[i] & 0b00001111];
}

void AES::Rcon(uint8_t *word, word_t row_num)
{
    std::memcpy(word, RCON[row_num], sizeof(word_t));
}

void AES::KeyExpansion(const uint8_t key[], uint8_t w[])
{
    uint8_t tmp [sizeof(word_t)];
    uint8_t rcon[sizeof(word_t)];

    std::memcpy(w, key, sizeof(word_t) * key_length_);

    for (size_t i = sizeof(word_t) * key_length_; i < sizeof(word_t) * AES::NB * (n_rounds_ + 1); i += sizeof(word_t)) {
        std::memcpy(tmp, &(w[i - 4]), sizeof(word_t));

        if ((i / sizeof(word_t)) % key_length_ == 0) {
            RotWord(tmp);
            SubWord(tmp);
            Rcon(rcon, (i / 4) / key_length_);
            XorWords(tmp, rcon, tmp);
        } else if (key_length_ > 6 && (i / sizeof(word_t)) % key_length_ == 4) {
            SubWord(tmp);
        }

        w[i + 0] = w[i + 0 - sizeof(word_t) * key_length_] ^ tmp[0];
        w[i + 1] = w[i + 1 - sizeof(word_t) * key_length_] ^ tmp[1];
        w[i + 2] = w[i + 2 - sizeof(word_t) * key_length_] ^ tmp[2];
        w[i + 3] = w[i + 3 - sizeof(word_t) * key_length_] ^ tmp[3];
    }
}

void AES::AddRoundKey(AES::State state, uint8_t *key)
{
    for (size_t i = 0; i < sizeof(word_t); i++)
    {
        for (size_t j = 0; j < AES::NB; j++)
            state[i][j] = state[i][j] ^ key[i + sizeof(word_t) * j];
    }
}

void AES::ShiftRow(AES::State state, word_t row_num, uint8_t shift)
{
    uint8_t tmp[AES::NB];
    for (size_t j = 0; j < AES::NB; j++)
        tmp[j] = state[row_num][(j + shift) % AES::NB];

    std::memcpy(state[row_num], tmp, AES::NB * sizeof(uint8_t));
}

void AES::ShiftRows(AES::State state)
{
    ShiftRow(state, 1, 1);
    ShiftRow(state, 2, 2);
    ShiftRow(state, 3, 3);
}

void AES::SubBytes(AES::State state)
{
    for (size_t i = 0; i < sizeof(word_t); i++)
    {
        for (size_t j = 0; j < AES::NB; j++)
        {
            uint8_t tmp = state[i][j];
            state[i][j] = AES::SBOX[tmp & 0b11110000][tmp & 0b00001111];
        }
    }
}

} // namespace cryper
