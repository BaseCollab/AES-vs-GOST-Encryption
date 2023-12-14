#ifndef ENCRYPTION_COMMON_FILE_H
#define ENCRYPTION_COMMON_FILE_H

#include <string>
#include <vector>
#include <stdio.h>
#include <stdint.h>
#include <sys/stat.h>

static inline size_t FileSize(const std::string& str)
{
    struct stat info = {};
    int res = stat(str.c_str(), &info);

    return res == -1 ? static_cast<size_t>(-1) :
                       static_cast<size_t>(info.st_size);
}

static inline bool FileRead(const std::string& str, std::vector<uint8_t>& out)
{
    FILE* in = fopen(str.c_str(), "rb");

    if (!in) {
        perror("The input file can't open");
        return false;
    }

    size_t size = FileSize(str);

    if (size == static_cast<size_t>(-1)) {
        perror("stat error");
        return false;
    }

    out.resize(size);

    size_t processed = fread(out.data(), sizeof(uint8_t), size, in);

    if (processed != size) {
        perror("fread error");
        return false;
    }

    fclose(in);

    return true;
}

static inline bool FileWrite(const std::string& str, const std::vector<uint8_t>& in)
{
    FILE* out = fopen(str.c_str(), "wb");

    if (!out) {
        perror("The output file can't open");
        return false;
    }

    size_t processed = fwrite(in.data(), sizeof(uint8_t), in.size(), out);

    if (processed != in.size()) {
        perror("fwrite error");
        return false;
    }

    fclose(out);

    return true;
}

#endif // ENCRYPTION_COMMON_FILE_H
