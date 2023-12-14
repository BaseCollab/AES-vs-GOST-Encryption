#include "argparser/parser.h"
#include <cstdlib>

int main(int argc, char *argv[])
{
    ArgParser parser(argc, argv);

    if (!parser.Parse()) return EXIT_FAILURE;


    return EXIT_SUCCESS;
}
