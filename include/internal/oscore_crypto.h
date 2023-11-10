/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */

#if !defined(TSM_INTERNAL_OSCORE_CRYPTO_H)
# define TSM_INTERNAL_OSCORE_CRYPTO_H
# pragma once

# include <tongsuo/oscore_cose.h>

int oscore_hkdf(cose_hkdf_alg_t hkdf_alg,
                TSM_STR *salt,
                TSM_STR *ikm,
                uint8_t *info,
                size_t info_len,
                uint8_t *okm,
                size_t okm_len);

#endif
