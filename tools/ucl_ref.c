/* ucl_ref.c — reference UCL/NRV2B compressor for the test suite.
 *
 * The decoder in qnxsec/ucl.py is checked against streams produced by the UCL
 * library itself, never against a compressor written here: otherwise a shared
 * misunderstanding of the format would pass unnoticed.
 *
 * build: cc -O2 -o ucl_ref ucl_ref.c -lucl
 * use:   ucl_ref compress <input> <output>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ucl/ucl.h>

int main(int argc, char **argv)
{
    if (argc != 4 || strcmp(argv[1], "compress") != 0) {
        fprintf(stderr, "usage: %s compress <input> <output>\n", argv[0]);
        return 2;
    }

    FILE *source = fopen(argv[2], "rb");
    if (!source) {
        perror("input");
        return 4;
    }
    fseek(source, 0, SEEK_END);
    long length = ftell(source);
    fseek(source, 0, SEEK_SET);
    if (length < 0) {
        fprintf(stderr, "cannot size the input\n");
        return 4;
    }
    unsigned char *data = malloc((size_t) length + 1);
    if (!data || fread(data, 1, (size_t) length, source) != (size_t) length) {
        fprintf(stderr, "cannot read the input\n");
        return 4;
    }
    fclose(source);

    ucl_uint packed_length = (ucl_uint) length + (ucl_uint) length / 8 + 256;
    unsigned char *packed = malloc(packed_length);
    if (!packed) {
        fprintf(stderr, "out of memory\n");
        return 4;
    }
    int code = ucl_nrv2b_99_compress(data, (ucl_uint) length, packed, &packed_length,
                                     NULL, 10, NULL, NULL);
    if (code != UCL_E_OK) {
        fprintf(stderr, "ucl_nrv2b_99_compress failed: %d\n", code);
        return 5;
    }

    FILE *output = fopen(argv[3], "wb");
    if (!output) {
        perror("output");
        return 4;
    }
    if (fwrite(packed, 1, packed_length, output) != packed_length) {
        fprintf(stderr, "cannot write the output\n");
        return 4;
    }
    fclose(output);
    printf("%ld %u\n", length, (unsigned) packed_length);
    return 0;
}
