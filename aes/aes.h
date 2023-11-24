#ifndef ENCRYPTION_AES_AES_H
#define ENCRYPTION_AES_AES_H

#include "common/macros.h"

#include <cstdint>
#include <cstddef>

namespace cryper
{

class AES
{
public:
    enum class KeyLength {
        AES_128,
        AES_192,
        AES_256
    };

public:
    NO_COPY_SEMANTIC(AES);
    NO_MOVE_SEMANTIC(AES);

    explicit AES(const KeyLength key_length = KeyLength::AES_256);
    ~AES() = default;

public:
    int Encrypt(const uint8_t *plaintext, const uint8_t *key, uint8_t *ciphertext) const;
    int Decrypt(const uint8_t *ciphertext, uint8_t *deciphertest) const;

private:
    static constexpr size_t NR_DEFAULT = 10; // amount of rounds
    static constexpr size_t NK_DEFAULT = 4;  // length of key in 32-bit words
    static constexpr size_t NB         = 4;  // length of input in 32-bit words

    using word_t = uint32_t;
    typedef word_t State[4][NB];

private:
    size_t n_rounds_   {NR_DEFAULT};
    size_t key_length_ {NK_DEFAULT};
};

} // namespace cryper

#endif // ENCRYPTION_AES_AES_H
