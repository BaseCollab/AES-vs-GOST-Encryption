#ifndef ENCRYPTION_BENCHMARKING_BENCHMARKING_H
#define ENCRYPTION_BENCHMARKING_BENCHMARKING_H

#include <cstdlib>
#include <cstddef>
#include <chrono>
#include <iostream>
#include <cstdint>

#include "aes/aes.h"
#include "chacha20/chacha20.h"
#include "gost_28147-89/gost.h"

void BenchmarkWorker(size_t init_size, size_t final_size);

#endif // ENCRYPTION_BENCHMARKING_BENCHMARKING_H
