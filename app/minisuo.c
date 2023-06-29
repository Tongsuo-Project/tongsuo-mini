/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tongsuo/minisuo.h>
#include <tongsuo/sm3.h>
#include <tongsuo/sm4.h>
#include "internal/mem.h"

typedef int (*algorithm_handler)(int argc, char **argv);

typedef struct {
    char *cmd;
    algorithm_handler handler;
} cmd_handler;

#ifdef TSM_HAVE_SM4
static int sm4_handler(int argc, char **argv)
{
    int ret = 1, i, mode = TSM_CIPH_MODE_CBC, flags = 0;
    long len;
    int outlen;
    size_t nread;
    unsigned char inbuf[1024];
    unsigned char outbuf[1024 + TSM_MAX_BLOCK_LENGTH];
    void *ctx = NULL;
    FILE *in = NULL, *out = NULL;
    char *infile = NULL, *outfile = NULL;
    unsigned char key[16];
    unsigned char iv[TSM_MAX_IV_LENGTH];

    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-mode") == 0) {
            i += 1;
            if (i >= argc) {
                fprintf(stderr, "no mode argument\n");
                return 1;
            }

            if (strcmp(argv[i], "cbc") == 0) {
                mode = TSM_CIPH_MODE_CBC;
            } else {
                fprintf(stderr, "wrong mode\n");
                return 1;
            }
        } else if (strcmp(argv[i], "-key") == 0) {
            i += 1;
            if (i >= argc) {
                fprintf(stderr, "no key\n");
                return 1;
            }
            if (strlen(argv[i]) != 32) {
                fprintf(stderr, "wrong key length\n");
                return 1;
            }

            len = 16;
            if (tsm_hex2bin(argv[i], key, &len) != TSM_OK || len != 16) {
                fprintf(stderr, "wrong key format\n");
                return 1;
            }
        } else if (strcmp(argv[i], "-iv") == 0) {
            i += 1;
            if (i >= argc) {
                fprintf(stderr, "no iv\n");
                return 1;
            }
            if (strlen(argv[i]) > sizeof(iv) * 2) {
                fprintf(stderr, "wrong iv length\n");
                return 1;
            }

            len = sizeof(iv);
            if (tsm_hex2bin(argv[i], iv, &len) != TSM_OK) {
                fprintf(stderr, "wrong iv format\n");
                return 1;
            }
        } else if (strcmp(argv[i], "-in") == 0) {
            i += 1;
            if (i >= argc) {
                fprintf(stderr, "no input\n");
                return 1;
            }

            infile = argv[i];
        } else if (strcmp(argv[i], "-out") == 0) {
            i += 1;
            if (i >= argc) {
                fprintf(stderr, "no output\n");
                return 1;
            }

            outfile = argv[i];
        } else if (strcmp(argv[i], "-enc") == 0) {
            flags |= TSM_CIPH_FLAG_ENCRYPT;
        } else if (strcmp(argv[i], "-dec") == 0) {
            flags |= TSM_CIPH_FLAG_DECRYPT;
        } else if (strcmp(argv[i], "-nopad") == 0) {
            flags |= TSM_CIPH_FLAG_NO_PAD;
        } else {
            fprintf(stderr, "unknown option %s\n", argv[i]);
            return 1;
        }
    }

    if (infile == NULL) {
        in = stdin;
    } else {
        in = fopen(infile, "rb");
        if (in == NULL) {
            fprintf(stderr, "cannot open input file %s\n", infile);
            return 1;
        }
    }

    if (outfile == NULL) {
        out = stdout;
    } else {
        out = fopen(outfile, "wb");
        if (out == NULL) {
            fprintf(stderr, "cannot open output file %s\n", outfile);
            return 1;
        }
    }

    ctx = tsm_sm4_init(mode, key, iv, flags);
    if (ctx == NULL)
        goto end;

    while (1) {
        nread = fread(inbuf, 1, sizeof(inbuf), in);
        if (nread != sizeof(inbuf) && ferror(in)) {
            fprintf(stderr, "read error\n");
            goto end;
        }

        if (tsm_sm4_update(ctx, inbuf, nread, outbuf, &outlen) != TSM_OK) {
            fprintf(stderr, "cipher update error\n");
            goto end;
        }

        if (fwrite(outbuf, 1, outlen, out) != (size_t)outlen) {
            fprintf(stderr, "write error\n");
            goto end;
        }

        if (feof(in))
            break;
    }

    if (tsm_sm4_final(ctx, outbuf, &outlen) != TSM_OK) {
        fprintf(stderr, "cipher final error\n");
        goto end;
    }

    if (fwrite(outbuf, 1, outlen, out) != (size_t)outlen) {
        fprintf(stderr, "write error\n");
        goto end;
    }

    ret = 0;
end:
    if (in != NULL && in != stdin)
        fclose(in);
    if (out != NULL && out != stdout)
        fclose(out);
    return ret;
}
#endif

#ifdef TSM_HAVE_SM3
static int sm3_handler(int argc, char **argv)
{
    unsigned char md[TSM_SM3_DIGEST_LEN];
    int i;

    if (argc == 3) {
        /* it must be: minisuo sm3 -h */
        if (strcmp(argv[2], "-h") == 0) {
            fprintf(stderr, "minisuo sm3 -in DATA\n");
            return 0;
        }
    }
    if (argc == 4) {
        if (strcmp(argv[2], "-in") != 0) {
            fprintf(stderr, "wrong usage\n");
            return 1;
        }
        /* calculate SM3 hash, take argv[3] as the input */
        if (tsm_sm3_oneshot(argv[3], strlen(argv[3]), md) != TSM_OK) {
            fprintf(stderr, "calculation error\n");
            return 1;
        }
        printf("SM3 Hash: ");
        for (i = 0; i < TSM_SM3_DIGEST_LEN; i++) {
            printf("%02X", (unsigned int)md[i]);
        }
        printf("\n");
        return 0;
    }
    fprintf(stderr, "wrong usage\n");
    return 1;
}
#endif

static cmd_handler cmds[] = {
#ifdef TSM_HAVE_SM3
    {"sm3", sm3_handler},
#endif
#ifdef TSM_HAVE_SM4
    {"sm4", sm4_handler},
#endif
    {NULL, NULL}};

#define N_CMD (int)(sizeof(cmds)/sizeof(cmds[0]))

void print_help(void)
{
    fprintf(stderr, "minisuo -v\n");
}

int main(int argc, char *argv[])
{
    int i, j;

    if (argc < 2) {
        print_help();
        exit(1);
    }

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
            fprintf(stderr, "%s\n", tsm_version());
            exit(0);
        } else {
            /* find a command and call corresponding handler */
            for (j = 0; j < N_CMD; j++) {
                if (strcmp(argv[i], cmds[j].cmd) == 0) {
                    return cmds[j].handler(argc, argv);
                }
            }
            /* unknown command */
            print_help();
            exit(1);
        }
    }

    return 0;
}
