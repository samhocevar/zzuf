/*
 *  zzuf - general purpose fuzzer
 *
 *  Copyright © 2002—2015 Sam Hocevar <sam@hocevar.net>
 *
 *  This program is free software. It comes without any warranty, to
 *  the extent permitted by applicable law. You can redistribute it
 *  and/or modify it under the terms of the Do What the Fuck You Want
 *  to Public License, Version 2, as published by the WTFPL Task Force.
 *  See http://www.wtfpl.net/ for more details.
 */

/*
 *  hex.c: hexadecimal data dump
 */

#include "config.h"

#if defined HAVE_STDINT_H
#   include <stdint.h>
#elif defined HAVE_INTTYPES_H
#   include <inttypes.h>
#endif
#if defined HAVE_ENDIAN_H
#   include <endian.h>
#endif
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "util/hex.h"

struct zzuf_hexdump
{
    /* Buffered line */
    uint8_t current_line[16];
    /* The previous line FIXME: not used yet */
    uint8_t prev_line[16];
    /* Number of bytes read so far */
    int64_t count;
};

zzuf_hexdump_t *zzuf_create_hex(void)
{
    zzuf_hexdump_t *ctx = malloc(sizeof(zzuf_hexdump_t));

    ctx->count = 0;

    return ctx;
}

static void print_hex(zzuf_hexdump_t *ctx, unsigned len)
{
    uint8_t *buf = ctx->current_line;
    uint32_t address = (uint32_t)(ctx->count - len);

    /* Create the hex dump */
    uint8_t hex[49] = "                                                ";
    for (unsigned i = 0; i < len; ++i)
    {
        static char const *hex2char = "0123456789abcdef";
        hex[i * 3 + (i >= 8)] = hex2char[buf[i] >> 4];
        hex[i * 3 + (i >= 8) + 1] = hex2char[buf[i] & 0xf];
    }

    /* Create the ASCII representation */
    uint8_t ascii[17] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    for (unsigned i = 0; i < len; ++i)
    {
        ascii[i] = (buf[i] >= 0x20 && buf[i] <= 0x7f) ? buf[i] : '.';
    }

    printf("%08x  %s  |%s|\n", address, hex, ascii);
}

void zz_hex_add(zzuf_hexdump_t *ctx, uint8_t *buf, unsigned len)
{
    unsigned buffered_len = (unsigned)(ctx->count & 15);

    while (len > 0)
    {
        /* Copy as many bytes as possible into our data buffer */
        unsigned to_copy = 16 - buffered_len;
        if (to_copy > len)
            to_copy = len;

        memcpy(ctx->current_line + buffered_len, buf, to_copy);
        buffered_len += to_copy;
        buf += to_copy;
        len -= to_copy;
        ctx->count += to_copy;

        /* If the buffer is full, print it */
        if (buffered_len == 16)
        {
            print_hex(ctx, 16);
            buffered_len = 0;
        }
    }

    fflush(stdout);
}

void zzuf_destroy_hex(zzuf_hexdump_t *ctx)
{
    /* Print the last line, if non-empty */
    if (ctx->count & 15)
        print_hex(ctx, (unsigned)(ctx->count & 15));

    /* Print the last offset */
    printf("%08x\n", (uint32_t)ctx->count);

    free(ctx);
    fflush(stdout);
}

