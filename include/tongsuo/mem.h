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
typedef struct tsm_str_s {
    size_t length;
    const uint8_t *s;
} TSM_STR;
# pragma pack()

/* Create a new TSM_STR object with the given data and length. Should be freed by calling
 * tsm_str_free() after use. */
TSM_STR *tsm_str_new(const uint8_t *data, size_t len);
/* Frees up the TSM_STR object. */
void tsm_str_free(TSM_STR *buf);
/* Duplicates the TSM_STR object. Should be freed by calling tsm_str_free() after use. */
TSM_STR *tsm_str_dup(TSM_STR *buf);
/* Creates a temp TSM_STR object with the given string. Must not be freed by calling tsm_str_free().
 */
TSM_STR *tsm_str(const char *string);
/* Creates a temp TSM_STR object with the given data and length. Must not be freed by calling
 * tsm_str_free(). */
TSM_STR *tsm_str_const(const uint8_t *data, size_t len);
/* Compares two TSM_STR. Return non-zero means equal, 0 means not equal. */
int tsm_str_equal(TSM_STR *a, TSM_STR *b);
/* Allocate a new buffer with size length. */
void *tsm_alloc(size_t size);
/* Allocate a new buffer with size length and zero it. */
void *tsm_calloc(size_t size);
/* Free the buffer. */
void tsm_free(void *ptr);
/* Zero the buffer. */
void tsm_memzero(void *ptr, size_t size);
/* Convert a hex buf with length buflen to binary. Return TSM_OK for success and others for failure.
 */
int tsm_hex2bin(const char *str, unsigned char *buf, size_t *buflen);
/* Convert a hex string with NUL(\0) as ending to buffer. The return pointer shoud be freed by
 * calling tsm_free() after use. */
unsigned char *tsm_hex2buf(const char *str);

# ifdef __cplusplus
}
# endif
#endif
