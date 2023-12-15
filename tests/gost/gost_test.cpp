#include <gtest/gtest.h>
#include <iostream>
#include <cstring>

#include "gost_28147-89/gost.h"

namespace gost {

TEST(GostTest, EncryptSimpleReplacement)
{
    constexpr size_t key_size = 32;
    uint8_t key[key_size] = {};
    for (size_t i = 0; i < key_size; i++) {
        key[i] = (rand() % 256);
    }

    // message size should be multiple of 8
    constexpr size_t message_size = 16;
    uint8_t message[message_size] = {};
    char text[] = "!!Hello world!!";
    std::memcpy(message, text, message_size * sizeof(uint8_t));

    uint8_t encr_msg[message_size] = {};
    Gost::Encrypt(key, message, message_size, encr_msg);

    uint8_t decr_msg[message_size] = {};
    Gost::Decrypt(key, encr_msg, message_size, decr_msg);

    for (size_t i = 0; i < message_size; ++i) {
        ASSERT_EQ(decr_msg[i], message[i]);
    }
}

TEST(GostTest, EncryptGamming)
{
    constexpr size_t key_size = 32;
    uint8_t key[key_size] = {};
    for (size_t i = 0; i < key_size; i++) {
        key[i] = (rand() % 256);
    }

    // message size should be multiple of 8
    constexpr size_t message_size = 13;
    uint8_t message[message_size] = {};
    char text[] = "Hello world!";
    std::memcpy(message, text, message_size * sizeof(uint8_t));

    uint64_t uint64_max_val = -1;
    uint64_t nonce = rand() % (uint64_max_val);

    uint8_t encr_msg[message_size] = {};
    Gost::EncryptCTR(nonce, key, message, message_size, encr_msg);

    uint8_t decr_msg[message_size] = {};
    Gost::DecryptCTR(nonce, key, encr_msg, message_size, decr_msg);

    for (size_t i = 0; i < message_size; ++i) {
        ASSERT_EQ(decr_msg[i], message[i]);
    }
}

TEST(GostTest, EncryptGammingBig)
{
    constexpr size_t key_size = 32;
    uint8_t key[key_size] = {};
    for (size_t i = 0; i < key_size; i++) {
        key[i] = (rand() % 256);
    }

    // message size should be multiple of 8
    const char text[] = "Hello world! Hello world! Hello world! Hello world! Hello world! Hello world!";
    uint8_t message[sizeof(text)] = {0};
    std::memcpy(message, text, sizeof(text));

    uint64_t uint64_max_val = -1;
    uint64_t nonce = rand() % (uint64_max_val);

    uint8_t encr_msg[sizeof(text)] = {};
    Gost::EncryptCTR(nonce, key, message, sizeof(text), encr_msg);

    uint8_t decr_msg[sizeof(text)] = {};
    Gost::DecryptCTR(nonce, key, encr_msg, sizeof(text), decr_msg);

    for (size_t i = 0; i < sizeof(text); ++i) {
        ASSERT_EQ(decr_msg[i], message[i]);
    }
}

} // namespace gost
