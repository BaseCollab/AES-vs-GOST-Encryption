#include <cstdlib>
#include <cstddef>
#include <chrono>
#include <iostream>
#include <cstdint>

#include "crypto_workers.h"

int main(int argc, char *argv[])
{
    (void) argc;
    (void) argv;    

    AESMainWorker(0x10, 0x1000000);

    return EXIT_SUCCESS;
}
