#include <aes/aes.h>

#include <gtest/gtest.h>

TEST(AES_Test, AES_Encryption)
{
    uint8_t key[] = {0x03, 0x45, 0x23, 0xff, 0xff, 0x45, 0x23, 0xee,
                     0x13, 0x15, 0x21, 0xf1, 0x1f, 0x35, 0x22, 0xe6};

    uint8_t data[] = {0x03, 0x45, 0x23, 0xff, 0xff, 0x45, 0x23, 0xee,
                      0x13, 0x15, 0x21, 0xf1, 0x1f, 0x35, 0x22, 0xe6};

    uint8_t enc_data[sizeof(data)] = {0};
    uint8_t dec_data[sizeof(data)] = {0};

    AES aes(AES::KeyLength::AES_128);
    aes.EncryptECB<false>(data, enc_data, sizeof(data), key);
    aes.DecryptECB<>(enc_data, dec_data, sizeof(data), nullptr);

    for (size_t i = 0; i < sizeof(data); ++i) {
        ASSERT_EQ(data[i], dec_data[i]);
    }
}
