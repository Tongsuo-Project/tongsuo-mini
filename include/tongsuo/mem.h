/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */

#if !defined(TSM_MEM_H)
# define TSM_MEM_H
# pragma once

# ifdef __cplusplus
extern "C" {
# endif

# include <stdlib.h>

# pragma pack(1)
typedef struct {
    size_t length;
    const uint8_t *s;
} TSM_STR;
# pragma pack()

TSM_STR *tsm_str_new(const uint8_t *data, size_t len);
void tsm_str_free(TSM_STR *buf);
TSM_STR *tsm_str_dup(TSM_STR *buf);
TSM_STR *tsm_str(const char *string);
TSM_STR *tsm_str_const(const uint8_t *data, size_t len);
int tsm_str_equal(TSM_STR *a, TSM_STR *b);

void *tsm_alloc(size_t size);
void *tsm_calloc(size_t size);
void tsm_free(void *ptr);
void tsm_memzero(void *ptr, size_t size);

int tsm_hex2bin(const char *str, unsigned char *buf, long *buflen);
unsigned char *tsm_hex2buf(const char *str);

# ifdef __cplusplus
}
# endif
#endif
