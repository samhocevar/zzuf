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
 *  md5.h: MD5 computation
 */

typedef struct zzuf_md5sum zzuf_md5sum_t;

extern zzuf_md5sum_t *zzuf_create_md5(void);
extern void zz_md5_add(zzuf_md5sum_t *ctx, uint8_t *buf, unsigned len);
extern void zzuf_destroy_md5(uint8_t *digest, zzuf_md5sum_t *ctx);

