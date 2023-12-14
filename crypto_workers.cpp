#include <cstdlib>
#include <cstddef>
#include <chrono>
#include <iostream>
#include <cstdint>
#include <aes/aes.h>

void AESMainWorker(size_t init_size, size_t final_size)
{
    uint8_t key[] = {0x03, 0x45, 0x23, 0xff, 0xff, 0x45, 0x23, 0xee,
                     0x13, 0x15, 0x21, 0xf1, 0x1f, 0x35, 0x22, 0xe6,
                     0x03, 0x45, 0x23, 0xff, 0xff, 0x45, 0x23, 0xee,
                     0x13, 0x15, 0x21, 0xf1, 0x1f, 0x35, 0x22, 0xe};
                
    uint8_t init_block[] = {0x11, 0x22, 0x33, 0x44, 0xff, 0x55, 0x23, 0xee,
                            0x93, 0x17, 0x71, 0x71, 0x1f, 0x35, 0x66, 0x33};

    for (size_t size = init_size; size <= final_size; size *= 2)
    {
        uint8_t *data_in  = new uint8_t[size];
        uint8_t *data_out = new uint8_t[size];
        
        if (data_in != nullptr) {
            for (size_t i = 0; i < size; ++i)
                data_in[i] = i * i;
        }

        {
            AES aes(AES::KeyLength::AES_256);
       
            auto time_start = std::chrono::high_resolution_clock::now();
            aes.EncryptCTR<false>(data_in, data_out, init_block, size, key);
            auto time_end = std::chrono::high_resolution_clock::now();

            const std::chrono::duration<double> diff = time_end - time_start;
            std::cout << size << "," << diff.count() << std::endl;
        }

        {
            // other regimes
       
            // auto time_start = std::chrono::high_resolution_clock::now();
            
            // auto time_end = std::chrono::high_resolution_clock::now();

            // const std::chrono::duration<double> diff = time_end - time_start;
            // std::cout << size << "," << diff.count() << std::endl;
        }

        delete [] data_in;
        delete [] data_out;
    }
}

