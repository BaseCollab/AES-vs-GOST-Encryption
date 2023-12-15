#include "benchmarking.h"

void BenchmarkWorker(size_t init_size, size_t final_size)
{
    std::cout << "encryption_regime,data_size,exec_time" << std::endl;

    uint8_t key[] = {0x03, 0x45, 0x23, 0xff, 0xff, 0x45, 0x23, 0xee,
                     0x13, 0x15, 0x21, 0xf1, 0x1f, 0x35, 0x22, 0xe6,
                     0x03, 0x45, 0x23, 0xff, 0xff, 0x45, 0x23, 0xee,
                     0x13, 0x15, 0x21, 0xf1, 0x1f, 0x35, 0x22, 0xe};

    uint8_t init_block[] = {0x11, 0x22, 0x33, 0x44, 0xff, 0x55, 0x23, 0xee,
                            0x93, 0x17, 0xb1, 0x71, 0x1f, 0x35, 0x66, 0x33};

    for (size_t size = init_size; size <= final_size; size *= 4)
    {
        uint8_t *data_in  = new uint8_t[size];
        uint8_t *data_out = new uint8_t[size];

        if (data_in != nullptr) {
            for (size_t i = 0; i < size; ++i)
                data_in[i] = i * i;
        }

        {
            AES __aes(AES::KeyLength::AES_256);

            auto __time_start = std::chrono::high_resolution_clock::now();
            __aes.EncryptCTR<false>(data_in, data_out, init_block, size, key);
            auto __time_end = std::chrono::high_resolution_clock::now();

            const std::chrono::duration<double> diff = __time_end - __time_start;
            std::cout << "aes256_default," << size << "," << diff.count() << std::endl;
        }

        {
            AES __aes(AES::KeyLength::AES_256, AES::HardwareSupport::AES_CRYPTO_EXTENSION);

            auto __time_start = std::chrono::high_resolution_clock::now();
            __aes.EncryptCTR<false>(data_in, data_out, init_block, size, key);
            auto __time_end = std::chrono::high_resolution_clock::now();

            const std::chrono::duration<double> diff = __time_end - __time_start;
            std::cout << "aes256_intrinsics," << size << "," << diff.count() << std::endl;
        }

        {
            chacha20::Key __key {key};
            chacha20::Nonce __nonce {0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00};

            auto __time_start = std::chrono::high_resolution_clock::now();
            chacha20::Cipher::Encrypt(__key, 1, __nonce, data_in, data_out, size);
            auto __time_end = std::chrono::high_resolution_clock::now();

            const std::chrono::duration<double> diff = __time_end - __time_start;
            std::cout << "chacha20," << size << "," << diff.count() << std::endl;
        }

        {
            uint64_t __nonce = 34235325;
            uint8_t __key[] = {
                0x03, 0x45, 0x23, 0xff, 0xff, 0x45, 0x23, 0xee,
                0x13, 0x15, 0x21, 0xf1, 0x1f, 0x35, 0x22, 0xe6,
                0x03, 0x45, 0x23, 0xff, 0xff, 0x45, 0x23, 0xee,
                0x13, 0x15, 0x21, 0xf1, 0x1f, 0x35, 0x22, 0xe1,
                0x03, 0x45, 0x23, 0xff, 0xff, 0x45, 0x23, 0xee,
                0x13, 0x15, 0x21, 0xf1, 0x1f, 0x35, 0x22, 0xe6,
                0x03, 0x45, 0x23, 0xff, 0xff, 0x45, 0x23, 0xee,
                0x13, 0x15, 0x21, 0xf1, 0x1f, 0x35, 0x22, 0xe
            };

            auto __time_start = std::chrono::high_resolution_clock::now();
            gost::Gost::EncryptCTR(__nonce, __key, data_in, size, data_out);
            auto __time_end = std::chrono::high_resolution_clock::now();

            const std::chrono::duration<double> diff = __time_end - __time_start;
            std::cout << "gost-28147-89," << size << "," << diff.count() << std::endl;
        }

        delete [] data_in;
        delete [] data_out;
    }
}

