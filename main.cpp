#include "argparser/parser.h"
#include "benchmark/benchmark.h"
#include "chacha20/chacha20.h"
#include "common/file.h"

#include <cstdlib>

int main(int argc, char *argv[])
{
    ArgParser parser(argc, argv);

    if (!parser.Parse()) return EXIT_FAILURE;

    ArgParser::EncryptMode encrypt_mode = parser.GetEnryptMode();
    // ArgParser::CipherMode cipher_mode = parser.GetCipherMode();

    if (encrypt_mode == ArgParser::EncryptMode::BENCHMARK)
    {
        Benchmark();
        return EXIT_SUCCESS;
    }

    std::vector<uint8_t> in;
    std::vector<uint8_t> out;

    FileRead(parser.GetInFileName(), in);
    out.resize(in.size());

    chacha20::Key key {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                       0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

    chacha20::Nonce nonce {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00};

    if (encrypt_mode == ArgParser::EncryptMode::ENCRYPT)
    {
        chacha20::Cipher::Encrypt(key, 1, nonce, in.data(), out.data(), in.size());
    }

    if (encrypt_mode == ArgParser::EncryptMode::DECRYPT)
    {
        chacha20::Cipher::Decrypt(key, 1, nonce, in.data(), out.data(), in.size());
    }

    FileWrite(parser.GetOutFileName(), out);

    return EXIT_SUCCESS;
}
