/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */

#include <string.h>
#include <tongsuo/ascon.h>
#include "internal/mem.h"
#include "test.h"

static char *schemestr;
static char *hex_msg;
static char *hex_md;

int test_ascon_hash(void)
{
    unsigned char *msg = tsm_hex2buf(hex_msg);
    unsigned char *md = tsm_hex2buf(hex_md);
    unsigned char buf[TSM_ASCON_HASH_LEN];
    int scheme;
    int outlen;

    if (strcmp(schemestr, "hash") == 0)
        scheme = TSM_ASCON_HASH;
    else
        scheme = TSM_ASCON_HASHA;

    ASSERT_OK(
        tsm_ascon_hash_oneshot(scheme, msg, msg == NULL ? 0 : strlen(hex_msg) / 2, buf, &outlen));

    ASSERT(outlen == TSM_ASCON_HASH_LEN);
    ASSERT(memcmp(buf, md, outlen) == 0);

    if (msg)
        tsm_free(msg);
    if (md)
        tsm_free(md);

    return 0;
}

int main(int argc, char **argv)
{
    int i;

    for (i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            if (i + 1 >= argc)
                break;

            if (argv[i + 1][0] == '-')
                continue;

            if (strcmp(argv[i], "-msg") == 0)
                hex_msg = argv[++i];
            else if (strcmp(argv[i], "-md") == 0)
                hex_md = argv[++i];
            else if (strcmp(argv[i], "-scheme") == 0)
                schemestr = argv[++i];
        }
    }

    TEST(test_ascon_hash);

    return 0;
}
