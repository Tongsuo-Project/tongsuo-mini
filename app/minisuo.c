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

typedef int (*algorithm_handler)(int argc, char **argv);

typedef struct {
    char *cmd;
    algorithm_handler handler;
} cmd_handler;

int sm3_handler(int argc, char **argv)
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

static cmd_handler cmds[] = {
    {"sm3", sm3_handler},
    {NULL, NULL}
};

#define N_CMD 1

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
