/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

/*
 * Performance test for various algorithms on xxx times 1MB random data, in avg.
 * Detailed performance indices:
 * SM3: hash(Mbps)
 * ASCON-Hash: Hash (in Mbps)
 * SM4: CBC Encrypt, CBC Decrypt (in Mbps)
 * ASCON-AEAD: Encrypt, Decrypt (in Mbps)
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <string.h>

#include <tongsuo/ascon.h>
#include <tongsuo/minisuo.h>
#include <tongsuo/mem.h>
#include <tongsuo/sm3.h>
#include <tongsuo/sm4.h>

static long long get_time(void);

/* iteration number, could be adjusted as required */
#define ITR_NUM       1000 * 1000
#define RND_DATA_SIZE 1024

/* time difference on each index */
struct perf_index {
    int sm3_hash;
    int ascon_hash;
    int sm4_cbc_enc;
    int sm4_cbc_dec;
    int ascon_aead_enc;
    int ascon_aead_dec;
};

/* final result in Mbps */
struct perf_result {
    long long sm3_hash_avg;
    long long ascon_hash_avg;
    long long sm4_cbc_enc_avg;
    long long sm4_cbc_dec_avg;
    long long ascon_aead_enc_avg;
    long long ascon_aead_dec_avg;
};

static long long get_time(void)
{
    /* just using gettimeofday() is adequate for our case */
    struct timeval tp;

    if (gettimeofday(&tp, NULL) != 0)
        return 0;
    else
        return (long long)(tp.tv_sec * 1000 * 1000 + tp.tv_usec);
}

int main(void)
{
    int ret = 1;
    struct perf_index *indices = NULL;
    struct perf_result result;
    int i = 0;
    unsigned char *rnd_data = NULL;
    long long start = 0, end = 0;
    unsigned char *out = NULL, *out2 = NULL;
    size_t outlen = 0, out2len = 0, inlen = RND_DATA_SIZE;
    unsigned char sm3_md[TSM_SM3_DIGEST_LEN];
    unsigned char ascon_md[TSM_ASCON_HASH_LEN];
    size_t mdlen = 0;
    unsigned char key[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                           0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned char iv[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                          0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    unsigned char ad[] = "performance test program";

    memset(&result, 0, sizeof(result));
    indices = tsm_alloc(sizeof(struct perf_index) * ITR_NUM);
    if (indices == NULL) {
        fprintf(stderr, "malloc error - indices\n");
        return -1;
    }
    memset(indices, 0, sizeof(struct perf_index) * ITR_NUM);

    out = tsm_alloc(inlen * 2);
    if (out == NULL) {
        goto err;
    }

    out2 = tsm_alloc(inlen * 2);
    if (out2 == NULL) {
        goto err;
    }

    for (; i < ITR_NUM; i++) {
        rnd_data = tsm_alloc(inlen);
        if (rnd_data == NULL) {
            goto err;
        }

        /* SM3 hash */
        start = get_time();
        if (tsm_sm3_oneshot(rnd_data, inlen, sm3_md) != TSM_OK) {
            goto err;
        }
        end = get_time();
        indices[i].sm3_hash = 1000 * 1000 * 8 / (end - start);

        /* ASCON hash */
        start = get_time();
        if (tsm_ascon_hash_oneshot(TSM_HASH_ASCON_HASH, rnd_data, inlen, ascon_md, &mdlen)
            != TSM_OK) {
            goto err;
        }
        end = get_time();
        indices[i].ascon_hash = 1000 * 1000 * 8 / (end - start);

        /* SM4 CBC encrypt */
        start = get_time();
        if (tsm_sm4_oneshot(TSM_CIPH_MODE_CBC, key, iv, rnd_data, inlen, out, &outlen,
                            TSM_CIPH_FLAG_ENCRYPT)
            != TSM_OK) {
            goto err;
        }
        end = get_time();
        indices[i].sm4_cbc_enc = 1000 * 1000 * 8 / (end - start);

        /* SM4 CBC decrypt */
        start = get_time();
        if (tsm_sm4_oneshot(TSM_CIPH_MODE_CBC, key, iv, out, outlen, out2, &out2len,
                            TSM_CIPH_FLAG_DECRYPT)
            != TSM_OK) {
            goto err;
        }
        end = get_time();
        indices[i].sm4_cbc_dec = 1000 * 1000 * 8 / (end - start);

        /* ASCON aead encrypt */
        start = get_time();
        if (tsm_ascon_aead_oneshot(TSM_ASCON_AEAD_128, key, iv, ad, sizeof(ad), rnd_data, inlen,
                                   out, &outlen, TSM_CIPH_FLAG_ENCRYPT)
            != TSM_OK) {
            goto err;
        }
        end = get_time();
        indices[i].ascon_aead_enc = 1000 * 1000 * 8 / (end - start);

        /* ASCON aead decrypt */
        start = get_time();
        if (tsm_ascon_aead_oneshot(TSM_ASCON_AEAD_128, key, iv, ad, sizeof(ad), out, outlen, out2,
                                   &out2len, TSM_CIPH_FLAG_DECRYPT)
            != TSM_OK) {
            goto err;
        }
        end = get_time();
        indices[i].ascon_aead_dec = 1000 * 1000 * 8 / (end - start);
#if 0
        fprintf(stdout, "sm3-hash: %d, "
                        "ascon-hash: %d, "
                        "sm4-cbc-enc: %d, "
                        "sm4-cbc-dec: %d, "
                        "ascon-aead-enc: %d, "
                        "ascon-aead-dec: %d\n",
                        indices[i].sm3_hash, indices[i].ascon_hash,
                        indices[i].sm4_cbc_enc, indices[i].sm4_cbc_dec,
                        indices[i].ascon_aead_enc, indices[i].ascon_aead_dec);
#endif
    }

    /* calculate the final average result */
    for (i = 0; i < ITR_NUM; i++) {
        result.sm3_hash_avg += indices[i].sm3_hash;
        result.ascon_hash_avg += indices[i].ascon_hash;
        result.sm4_cbc_enc_avg += indices[i].sm4_cbc_enc;
        result.sm4_cbc_dec_avg += indices[i].sm4_cbc_dec;
        result.ascon_aead_enc_avg += indices[i].ascon_aead_enc;
        result.ascon_aead_dec_avg += indices[i].ascon_aead_dec;
    }

    result.sm3_hash_avg /= ITR_NUM;
    result.ascon_hash_avg /= ITR_NUM;
    result.sm4_cbc_dec_avg /= ITR_NUM;
    result.sm4_cbc_enc_avg /= ITR_NUM;
    result.ascon_aead_enc_avg /= ITR_NUM;
    result.ascon_aead_dec_avg /= ITR_NUM;

    fprintf(stdout,
            "Final result:\n"
            "sm3-hash: %lld kbps\n"
            "ascon-hash: %lld kbps\n"
            "sm4-cbc-enc: %lld kbps\n"
            "sm4-cbc-dec: %lld kbps\n"
            "ascon-aead-enc: %lld kbps\n"
            "ascon-aead-dec: %lld kbps\n",
            result.sm3_hash_avg, result.ascon_hash_avg, result.sm4_cbc_enc_avg,
            result.sm4_cbc_dec_avg, result.ascon_aead_enc_avg, result.ascon_aead_dec_avg);

    ret = 0;
err:

    tsm_free(out);
    tsm_free(out2);
    tsm_free(indices);
    tsm_free(rnd_data);

    return ret;
}
