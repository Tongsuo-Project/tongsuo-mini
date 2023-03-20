/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */

#include <internal/log.h>
#include <internal/mem.h>
#include <internal/pool.h>
#include <stdlib.h>

typedef struct {
    unsigned char *last;
    unsigned char *end;
    tsm_pool_t *next;
    int failed;
} tsm_pool_data_t;

struct tsm_pool_s {
    tsm_pool_data_t d;
    tsm_pool_t *current;
};

static void *tsm_palloc_block(tsm_pool_t *pool, size_t size);

tsm_pool_t *ngx_create_pool(size_t size)
{
    tsm_pool_t *p;

    p = tsm_alloc(size);
    if (p == NULL) {
        return NULL;
    }

    p->d.last = (unsigned char *)p + sizeof(tsm_pool_t);
    p->d.end = (unsigned char *)p + size;
    p->d.next = NULL;
    p->d.failed = 0;

    size = size - sizeof(tsm_pool_t);
    p->current = p;

    tsm_debug("create pool %p:%z", p, size);
    return p;
}

void tsm_destroy_pool(tsm_pool_t *pool)
{
    tsm_pool_t *p, *n;
    tsm_debug("destroy pool %p", pool);

    for (p = pool, n = pool->d.next;; p = n, n = n->d.next) {
        tsm_free(p);

        if (n == NULL) {
            break;
        }
    }
}

void *tsm_palloc(tsm_pool_t *pool, size_t size)
{
    unsigned char *m;
    tsm_pool_t *p;

    tsm_debug("palloc %p:%z", pool, size);

    p = pool->current;

    do {
        m = p->d.last;

        if ((size_t)(p->d.end - m) >= size) {
            p->d.last = m + size;

            return m;
        }

        p = p->d.next;

    } while (p);

    return tsm_palloc_block(pool, size);
}

static void *tsm_palloc_block(tsm_pool_t *pool, size_t size)
{
    unsigned char *m;
    size_t psize;
    tsm_pool_t *p, *new;

    psize = (size_t)(pool->d.end - (unsigned char *)pool);

    m = tsm_alloc(psize);
    if (m == NULL) {
        return NULL;
    }

    new = (tsm_pool_t *)m;

    new->d.end = m + psize;
    new->d.next = NULL;
    new->d.failed = 0;

    m += sizeof(tsm_pool_data_t);
    new->d.last = m + size;

    for (p = pool->current; p->d.next; p = p->d.next) {
        if (p->d.failed++ > 4) {
            pool->current = p->d.next;
        }
    }

    p->d.next = new;

    return m;
}

void *tsm_pcalloc(tsm_pool_t *pool, size_t size)
{
    void *p;

    p = tsm_palloc(pool, size);
    if (p) {
        tsm_memzero(p, size);
    }

    tsm_debug("pcalloc %p:%p:%z", pool, p, size);
    return p;
}
