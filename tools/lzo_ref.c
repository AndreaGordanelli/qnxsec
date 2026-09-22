/* lzo_ref.c — reference LZO1X compressor for the test suite.
 *
 * The decoder in qnxsec/lzo.py is checked against streams produced by the LZO
 * library itself, so the tests never validate the implementation against its
 * own idea of the format: the reference bytes come from the same library QNX
 * links against.
 *
 * build: cc -O2 -o lzo_ref lzo_ref.c -llzo2
 * use:   lzo_ref compress <input> <output>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <lzo/lzo1x.h>

int main(int argc, char **argv)
{
    if (argc != 4 || strcmp(argv[1], "compress") != 0) {
        fprintf(stderr, "usage: %s compress <input> <output>\n", argv[0]);
        return 2;
    }
    if (lzo_init() != LZO_E_OK) {
        fprintf(stderr, "lzo_init failed\n");
        return 3;
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

    lzo_uint packed_length = (lzo_uint) length + (lzo_uint) length / 16 + 64 + 3;
    unsigned char *packed = malloc(packed_length);
    void *work = malloc(LZO1X_1_MEM_COMPRESS);
    if (!packed || !work) {
        fprintf(stderr, "out of memory\n");
        return 4;
    }
    if (lzo1x_1_compress(data, (lzo_uint) length, packed, &packed_length, work) != LZO_E_OK) {
        fprintf(stderr, "lzo1x_1_compress failed\n");
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
    printf("%ld %lu\n", length, (unsigned long) packed_length);
    return 0;
}
