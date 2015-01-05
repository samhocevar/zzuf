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
 *  md5.h: MD5 computation
 */

struct md5;

extern struct zz_md5 *zz_md5_init(void);
extern void zz_md5_add(struct zz_md5 *ctx, uint8_t *buf, unsigned len);
extern void zz_md5_fini(uint8_t *digest, struct zz_md5 *ctx);

