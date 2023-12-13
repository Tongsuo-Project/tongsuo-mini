/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */

#include <string.h>
#include "test.h"
#include <tongsuo/minisuo.h>
#include <tongsuo/mem.h>
#include <tongsuo/sm3.h>

int test_sm3_hash(const char *hex_input, const char *hex_output)
{
    unsigned char *input = tsm_hex2buf(hex_input);
    unsigned char *output = tsm_hex2buf(hex_output);
    unsigned char md[TSM_SM3_DIGEST_LEN];

    ASSERT_OK(tsm_sm3_oneshot(input, strlen(hex_input) / 2, md));
    ASSERT(memcmp(md, output, TSM_SM3_DIGEST_LEN) == 0);

    tsm_free(input);
    tsm_free(output);

    return TSM_OK;
}

int main(int argc, char **argv)
{
    int i;
    const char *input = NULL;
    const char *output = NULL;

    for (i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            if (i + 1 >= argc)
                break;

            if (argv[i + 1][0] == '-')
                continue;

            if (strcmp(argv[i], "-input") == 0)
                input = argv[++i];
            else if (strcmp(argv[i], "-output") == 0)
                output = argv[++i];
            else
                return 1;
        }
    }

    TEST_EX(test_sm3_hash, input, output);

    return 0;
}
