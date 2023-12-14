#ifndef ENCRYPTION_ARGPARSER_PARSER_H
#define ENCRYPTION_ARGPARSER_PARSER_H

#include <string>
#include <cstring>
#include <stdint.h>
#include <getopt.h>

#include "common/macros.h"

class ArgParser
{
public:

    enum class EncryptMode : uint8_t
    {
        INVALID_MODE = static_cast<uint8_t>(-1),

        ENCRYPT  = 1,
        DECRYPT  = 2,
        BENCHMARK = 3
    };

    enum class CipherMode : uint8_t
    {
        INVALID_MODE = static_cast<uint8_t>(-1),

        AES_ECB_128 =  0,
        AES_ECB_192 =  1,
        AES_ECB_256 =  2,
        AES_CBC_128 =  3,
        AES_CBC_192 =  4,
        AES_CBC_256 =  5,
        AES_CTR_128 =  6,
        AES_CTR_192 =  7,
        AES_CTR_256 =  8,

        GOST_ECB    =  9,
        GOST_CTR    = 10,

        CHACHA20    = 11
    };

    enum class OptNames : char
    {
        OPT_INFILE   = 'i',
        OPT_OUTFILE  = 'o',
        OPT_HELP     = 'h',
        OPT_CIPHER   = 'c',
        OPT_ENC_MODE = 'e'
    };

    NO_COPY_SEMANTIC(ArgParser);
    NO_MOVE_SEMANTIC(ArgParser);

    explicit ArgParser(int argc, char *argv[]) : argc_(argc), argv_(argv) {};
    ~ArgParser() = default;

    bool Parse();

    EncryptMode GetEnryptMode() const
    {
        return encrypt_mode_;
    }

    CipherMode GetCipherMode() const
    {
        return cipher_mode_;
    }

    const std::string &GetInFileName() const
    {
        return in_filename_;
    }

    const std::string &GetOutFileName() const
    {
        return out_filename_;
    }

private:

    void PrintHelp();

    EncryptMode CheckEncryptMode(const char* str) const
    {
        if (strcmp(str, "encrypt") == 0) {
            return EncryptMode::ENCRYPT;
        } else if (strcmp(str, "decrypt") == 0) {
            return EncryptMode::DECRYPT;
        } else if (strcmp(str, "bencmark") == 0) {
            return EncryptMode::BENCHMARK;
        }

        return EncryptMode::INVALID_MODE;
    }


    CipherMode CheckCipherMode(const char* str) const
    {
        if (strcmp(str, "aes_ecb_128") == 0) {
            return CipherMode::AES_ECB_128;
        } else if (strcmp(str, "aes_ecb_192") == 0) {
            return CipherMode::AES_ECB_192;
        } else if (strcmp(str, "aes_ecb_256") == 0) {
            return CipherMode::AES_ECB_256;
        } else if (strcmp(str, "aes_cbc_128") == 0) {
            return CipherMode::AES_CBC_128;
        } else if (strcmp(str, "aes_cbc_192") == 0) {
            return CipherMode::AES_CBC_192;
        } else if (strcmp(str, "aes_cbc_256") == 0) {
            return CipherMode::AES_CBC_256;
        } else if (strcmp(str, "aes_ctr_128") == 0) {
            return CipherMode::AES_CTR_128;
        } else if (strcmp(str, "aes_ctr_192") == 0) {
            return CipherMode::AES_CTR_192;
        } else if (strcmp(str, "aes_ctr_256") == 0) {
            return CipherMode::AES_CTR_256;
        } else if (strcmp(str, "gost_ecb") == 0) {
            return CipherMode::GOST_ECB;
        } else if (strcmp(str, "gost_ctr") == 0) {
            return CipherMode::GOST_CTR;
        } else if (strcmp(str, "chacha20") == 0) {
            return CipherMode::CHACHA20;
        }

        return CipherMode::INVALID_MODE;
    }

    int argc_ {0};
    char **argv_ {nullptr};

    EncryptMode encrypt_mode_ {EncryptMode::INVALID_MODE};
    CipherMode cipher_mode_ {CipherMode::INVALID_MODE};

    std::string in_filename_;
    std::string out_filename_;
};

#endif // ENCRYPTION_ARGPARSER_PARSER_H
