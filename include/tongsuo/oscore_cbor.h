/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */

#if !defined(TSM_OSCORE_CBOR_H)
# define TSM_OSCORE_CBOR_H
# pragma once

# ifdef __cplusplus
extern "C" {
# endif

# include <stddef.h>
# include <stdint.h>

/* CBOR major types */
# define CBOR_UNSIGNED_INTEGER 0
# define CBOR_NEGATIVE_INTEGER 1
# define CBOR_BYTE_STRING      2
# define CBOR_TEXT_STRING      3
# define CBOR_ARRAY            4
# define CBOR_MAP              5
# define CBOR_TAG              6
# define CBOR_SIMPLE_VALUE     7
# define CBOR_FLOATING_POINT   7

# define CBOR_FALSE            20
# define CBOR_TRUE             21
# define CBOR_NULL             22

/* Write a CBOR nil to the buffer. Returns the number of bytes written. */
size_t tsm_oscore_cbor_put_nil(uint8_t **buffer, size_t *buf_size);
/* Write a CBOR true to the buffer. Returns the number of bytes written. */
size_t tsm_oscore_cbor_put_true(uint8_t **buffer, size_t *buf_size);
/* Write a CBOR false to the buffer. Returns the number of bytes written. */
size_t tsm_oscore_cbor_put_false(uint8_t **buffer, size_t *buf_size);
/* Write CBOR text with length text_len to the buffer. Returns the number of bytes written. */
size_t tsm_oscore_cbor_put_text(uint8_t **buffer, size_t *buf_size, const char *text,
                                size_t text_len);
/* Write CBOR array with elements size to the buffer. Returns the number of bytes written. */
size_t tsm_oscore_cbor_put_array(uint8_t **buffer, size_t *buf_size, size_t elements);
/* Write CBOR bytes with length bytes_len to the buffer. Returns the number of bytes written. */
size_t tsm_oscore_cbor_put_bytes(uint8_t **buffer, size_t *buf_size, const uint8_t *bytes,
                                 size_t bytes_len);
/* Write CBOR map with elements size to the buffer. Returns the number of bytes written. */
size_t tsm_oscore_cbor_put_map(uint8_t **buffer, size_t *buf_size, size_t elements);
/* Write CBOR integer to the buffer. Returns the number of bytes written.
 */
size_t tsm_oscore_cbor_put_number(uint8_t **buffer, size_t *buf_size, int64_t value);
/* Write CBOR simple value to the buffer. Returns the number of bytes written. */
size_t tsm_oscore_cbor_put_simple_value(uint8_t **buffer, size_t *buf_size, uint8_t value);
/* Write CBOR unsigned integer to the buffer. Returns the number of bytes written. */
size_t tsm_oscore_cbor_put_unsigned(uint8_t **buffer, size_t *buf_size, uint64_t value);
/* Write CBOR tag to the buffer. Returns the number of bytes written. */
size_t tsm_oscore_cbor_put_tag(uint8_t **buffer, size_t *buf_size, uint64_t value);
/* Write CBOR negative integer to the buffer. Returns the number of bytes written. */
size_t tsm_oscore_cbor_put_negative(uint8_t **buffer, size_t *buf_size, int64_t value);
/* Get the type of the next CBOR element in the buffer. */
uint8_t tsm_oscore_cbor_get_next_element(const uint8_t **buffer, size_t *buf_size);
/* Get the size of the next CBOR element in the buffer. */
size_t tsm_oscore_cbor_get_element_size(const uint8_t **buffer, size_t *buf_size);
/* Test if the data buffer contaions a complete element. */
uint8_t tsm_oscore_cbor_elem_contained(const uint8_t *data, size_t *buf_size, uint8_t *end);
/* Gets a negative or positive number from data. Returns TSM_OK means success, otherwise returns
 * a specific error code. */
int tsm_oscore_cbor_get_number(const uint8_t **data, size_t *buf_size, int64_t *value);
/* Gets a simple value from data; returns TSM_OK means success, otherwise returns a specific error
 * code.otherwise returns a specific error code. */
int tsm_oscore_cbor_get_simple_value(const uint8_t **data, size_t *buf_size, uint8_t *value);
/* Gets a negative integer from buffer. */
int64_t tsm_oscore_cbor_get_negative_integer(const uint8_t **buffer, size_t *buf_size);
/* Gets an unsigned integer from buffer. */
uint64_t tsm_oscore_cbor_get_unsigned_integer(const uint8_t **buffer, size_t *buf_size);
/* Gets a CBOR string with length size from buffer. */
void tsm_oscore_cbor_get_string(const uint8_t **buffer, size_t *buf_size, char *str, size_t size);
/* Gets a CBOR array with length size from buffer. */
void tsm_oscore_cbor_get_array(const uint8_t **buffer, size_t *buf_size, uint8_t *arr, size_t size);

/* Gets a string array and fills the result. The length of result is written to len. result is
 * allocated by tsm_alloc(), should be freed by calling tsm_free() after use. Returns TSM_OK for
 * success and others for failure. */
int tsm_oscore_cbor_get_string_array(const uint8_t **data, size_t *buf_size, uint8_t **result,
                                     size_t *len);
/* Strips the value of the cbor element into result and writes size in len. result is allocated by
 * tsm_alloc(), should be freed by calling tsm_free() after use. Returns TSM_OK for success and
 * others for failure. */
int tsm_oscore_cbor_strip_value(const uint8_t **data, size_t *buf_size, uint8_t **result,
                                size_t *len);
# ifdef __cplusplus
}
# endif
#endif
