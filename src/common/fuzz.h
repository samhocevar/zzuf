/*
 *  zzuf - general purpose fuzzer
 *  Copyright (c) 2006-2010 Sam Hocevar <sam@hocevar.net>
 *                All Rights Reserved
 *
 *  This program is free software. It comes without any warranty, to
 *  the extent permitted by applicable law. You can redistribute it
 *  and/or modify it under the terms of the Do What The Fuck You Want
 *  To Public License, Version 2, as published by Sam Hocevar. See
 *  http://sam.zoy.org/wtfpl/COPYING for more details.
 */

/*
 *  fuzz.h: fuzz functions
 */

extern void _zz_fuzzing(char const *);
extern void _zz_bytes(char const *);
extern void _zz_list(char const *);
extern void _zz_protect(char const *);
extern void _zz_refuse(char const *);

extern void _zz_fuzz(int, volatile uint8_t *, int64_t);

