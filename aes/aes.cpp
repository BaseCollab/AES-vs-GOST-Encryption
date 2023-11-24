#include "aes.h"

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

} // namespace cryper
