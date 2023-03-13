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

void print_help(void)
{
    fprintf(stderr, "minisuo -v\n");
}

int main(int argc, char *argv[])
{
    int i;

    if (argc < 2) {
        print_help();
        exit(1);
    }

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
            fprintf(stderr, "%s\n", tsm_version());
            exit(0);
        } else {
            print_help();
            exit(1);
        }
    }

    return 0;
}
