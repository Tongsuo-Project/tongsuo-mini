/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */

#include <tongsuo/minisuo.h>
#include <stdio.h>
#include <string.h>

/* Tongsuo Mini xxx.yyy.zzz-pre255 */
static char version[32];

const char *tsm_version_text(void)
{
    char *p = version;
    char *end = version + sizeof(version);
    char tag[8];

    switch (TSM_VERSION_TAG & 0xff) {
    case 0:
        strcpy(tag, "-dev");
        break;
    case 0xff:
        tag[0] = '\0';
        break;
    default:
        snprintf(tag, sizeof(tag), "-pre%u", TSM_VERSION_TAG & 0xff);
        break;
    }

    p += snprintf(p, end - p, "Tongsuo Mini %d.%d.%d%s", TSM_VERSION_MAJOR, TSM_VERSION_MINOR,
                  TSM_VERSION_PATCH, tag);

    return version;
}
