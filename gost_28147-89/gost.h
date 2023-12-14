#ifndef ENCRYPTION_GOST_GOST_H
#define ENCRYPTION_GOST_GOST_H

#include <cstdint>
#include <cstddef>

namespace gost {

class State;

class Gost {
public:
    static constexpr size_t BLOCK_SIZE = 8;
    static constexpr size_t ROUNDS_NMB = 32;

public:
    static bool Encrypt(uint8_t *key, uint8_t *msg, size_t m_size, uint8_t *out);
    static bool Decrypt(uint8_t *key, uint8_t *ciphertext, size_t c_size, uint8_t *out);

    static bool EncryptCTR(uint64_t nonce, uint8_t *key, uint8_t *msg, size_t m_size, uint8_t *out);
    static bool DecryptCTR(uint64_t nonce, uint8_t *key, uint8_t *ciphertext, size_t c_size, uint8_t *out);

    static uint32_t Function(uint32_t A_i, uint32_t X_i);

private:
    static uint64_t CreateGamma(State *state, uint8_t *key);
};

} // namespace gost

#endif // ENCRYPTION_GOST_GOST_H
