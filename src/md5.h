/*
 *  zzuf - general purpose fuzzer
 *  Copyright (c) 2002-2010 Sam Hocevar <sam@hocevar.net>
 *                All Rights Reserved
 *
 *  This program is free software. It comes without any warranty, to
 *  the extent permitted by applicable law. You can redistribute it
 *  and/or modify it under the terms of the Do What The Fuck You Want
 *  To Public License, Version 2, as published by Sam Hocevar. See
 *  http://sam.zoy.org/wtfpl/COPYING for more details.
 */

/*
 *  md5.h: MD5 computation
 */

struct md5;

extern struct md5 *_zz_md5_init(void);
extern void _zz_md5_add(struct md5 *ctx, uint8_t *buf, unsigned len);
extern void _zz_md5_fini(uint8_t *digest, struct md5 *ctx);

