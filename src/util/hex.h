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

#pragma once

/*
 *  hex.h: hexadecimal data dump
 */

typedef struct zzuf_hexdump zzuf_hexdump_t;

extern zzuf_hexdump_t *zzuf_create_hex(void);
extern void zz_hex_add(zzuf_hexdump_t *ctx, uint8_t *buf, unsigned len);
extern void zzuf_destroy_hex(zzuf_hexdump_t *ctx);

