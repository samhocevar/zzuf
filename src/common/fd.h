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
 *  fd.h: file descriptor functions
 */

extern void _zz_include(char const *);
extern void _zz_exclude(char const *);
extern void _zz_setseed(int32_t);
extern void _zz_setratio(double, double);
extern double _zz_getratio(void);
extern void _zz_setautoinc(void);
extern void _zz_fd_init(void);
extern void _zz_fd_fini(void);

extern int _zz_mustwatch(char const *);
extern int _zz_iswatched(int);
extern void _zz_register(int);
extern void _zz_unregister(int);
extern void _zz_lock(int);
extern void _zz_unlock(int);
extern int _zz_islocked(int);
extern int _zz_isactive(int);
extern int64_t _zz_getpos(int);
extern void _zz_setpos(int, int64_t);
extern void _zz_addpos(int, int64_t);
extern void _zz_setfuzzed(int, int);
extern int _zz_getfuzzed(int);

extern struct fuzz *_zz_getfuzz(int);

