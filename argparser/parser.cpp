#include "parser.h"

bool ArgParser::Parse()
{
    if (argc_ < 2) {
        PrintHelp();
        return false;
    }

    static struct option options[] = {{"help", no_argument, 0, static_cast<int>(OptNames::OPT_HELP)},
                                      {0, 0, 0, 0}};

    int opt = 0;

    uint32_t mask = 0;

    while ((opt = getopt_long(argc_, argv_, "e:c:i:o:h", options, NULL)) != -1) {
        switch (static_cast<OptNames>(opt)) {

            case OptNames::OPT_ENC_MODE: {
                encrypt_mode_ = CheckEncryptMode(optarg);

                if (encrypt_mode_ == EncryptMode::INVALID_MODE)
                    return false;

                mask |= (1 << 0);
                break;
            }

            case OptNames::OPT_CIPHER: {
                cipher_mode_ = CheckCipherMode(optarg);

                if (cipher_mode_ == CipherMode::INVALID_MODE)
                    return false;

                mask |= (1 << 1);
                break;
            }

            case OptNames::OPT_INFILE: {
                in_filename_ = optarg;
                mask |= (1 << 2);
                break;
            }

            case OptNames::OPT_OUTFILE: {
                out_filename_ = optarg;
                mask |= (1 << 3);
                break;
            }

            case OptNames::OPT_HELP:
                PrintHelp();
                exit(EXIT_SUCCESS);
            default:
                return false;
        }
    }

    if (mask != 0x0F) {
        PrintHelp();
        return false;
    }

    return true;
}

void ArgParser::PrintHelp()
{
    printf("USAGE: %s -e <ENCRYPT_MODE> [options]\n"
           "\tEncryptions options:\n", argv_[0]);
    printf("-c <CIPHER_MODE>  -- cipher mode.\n");
    printf("-i <in_filename>  -- input file.\n");
    printf("-h                -- print this help and exit.\n");
    printf("-o <out_filename> -- output file.\n");
}
