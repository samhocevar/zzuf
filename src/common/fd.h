/*
 *  zzuf - general purpose fuzzer
 *
 *  Copyright © 2002—2015 Sam Hocevar <sam@hocevar.net>
 *              2012 Kévin Szkudłapski <kszkudlapski@quarkslab.com>
 *
 *  This program is free software. It comes without any warranty, to
 *  the extent permitted by applicable law. You can redistribute it
 *  and/or modify it under the terms of the Do What the Fuck You Want
 *  to Public License, Version 2, as published by the WTFPL Task Force.
 *  See http://www.wtfpl.net/ for more details.
 */

#pragma once

/*
 *  fd.h: file descriptor functions
 */

#include "common/common.h"

#include <stdint.h>
#include <wchar.h>

extern void zzuf_include_pattern(char const *);
extern void zzuf_exclude_pattern(char const *);
extern void zzuf_set_seed(int32_t);
extern void zzuf_set_ratio(double, double);
extern double zzuf_get_ratio(void);
extern void zzuf_set_auto_increment(void);
extern void _zz_fd_init(void);
extern void _zz_fd_fini(void);

extern int _zz_mustwatch(char const *);
extern int _zz_mustwatchw(wchar_t const *);
extern int _zz_iswatched(int);
extern void _zz_register(int);
extern void _zz_unregister(int);
extern void _zz_lockfd(int);
extern void _zz_unlock(int);
extern int _zz_islocked(int);
extern int _zz_isactive(int);
extern int64_t _zz_getpos(int);
extern void _zz_setpos(int, int64_t);
extern void _zz_addpos(int, int64_t);
extern void _zz_setfuzzed(int, int);
extern int _zz_getfuzzed(int);

extern fuzz_context_t *_zz_getfuzz(int);

