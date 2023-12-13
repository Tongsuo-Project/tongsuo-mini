/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */

#include <tongsuo/mem.h>
#include <tongsuo/hmac.h>
#include <tongsuo/ascon.h>
#include "test.h"
#include <string.h>

int test_ascon_hmac(int hash, const char *hex_key, const char *hex_msg, const char *hex_tag)
{
    unsigned char *key = tsm_hex2buf(hex_key);
    unsigned char *msg = tsm_hex2buf(hex_msg);
    unsigned char *tag = tsm_hex2buf(hex_tag);
    unsigned char buf[TSM_ASCON_HMAC_LEN];
    size_t outlen;

    ASSERT_OK(tsm_hmac_oneshot(hash, key, strlen(hex_key) / 2, msg,
                               msg == NULL ? 0 : strlen(hex_msg) / 2, buf, &outlen));

    ASSERT(outlen == TSM_ASCON_HMAC_LEN);
    ASSERT(memcmp(buf, tag, outlen) == 0);

    if (key)
        tsm_free(key);
    if (msg)
        tsm_free(msg);
    if (tag)
        tsm_free(tag);

    return 0;
}

int main(int argc, char **argv)
{
    int i;
    int hash;
    const char *hex_key = NULL;
    const char *hex_msg = NULL;
    const char *hex_tag = NULL;
    const char *algo = NULL;

    for (i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            if (i + 1 >= argc)
                break;

            if (argv[i + 1][0] == '-')
                continue;

            if (strcmp(argv[i], "-algo") == 0)
                algo = argv[++i];
            else if (strcmp(argv[i], "-key") == 0)
                hex_key = argv[++i];
            else if (strcmp(argv[i], "-msg") == 0)
                hex_msg = argv[++i];
            else if (strcmp(argv[i], "-tag") == 0)
                hex_tag = argv[++i];
            else
                return 1;
        }
    }

    if (strcmp(algo, "ascon-hmac") == 0)
        hash = TSM_HASH_ASCON_HASH;
    else if (strcmp(algo, "ascon-hmaca") == 0)
        hash = TSM_HASH_ASCON_HASHA;
    else
        return 1;

    TEST_EX(test_ascon_hmac, hash, hex_key, hex_msg, hex_tag);

    return 0;
}
