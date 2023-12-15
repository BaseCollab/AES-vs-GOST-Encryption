#ifndef ENCRYPTION_GOST_KEY_H
#define ENCRYPTION_GOST_KEY_H

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <array>

namespace gost {

class Key {
public:
    static constexpr size_t KEY_LENGTH = 32;  // bytes
    static constexpr size_t SUBKEY_LENTH = 4; // bytes
    static constexpr size_t SUBKEYS_NMB = KEY_LENGTH / SUBKEY_LENTH;

    explicit Key(uint8_t *key) : key_(key)
    {
        std::memcpy(subkeys_, key_, KEY_LENGTH * sizeof(uint8_t));
    }

    uint32_t GetSubkey(size_t idx)
    {
        return subkeys_[idx];
    }

    ~Key() = default;

private:
    uint8_t *key_ {nullptr};
    uint32_t subkeys_[SUBKEYS_NMB];
};

} // namespace gost

#endif // ENCRYPTION_GOST_KEY_H
