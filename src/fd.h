/*
 *  zzuf - general purpose fuzzer
 *  Copyright (c) 2006 Sam Hocevar <sam@zoy.org>
 *                All Rights Reserved
 *
 *  $Id$
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

extern void _zz_fd_init(void);
extern void _zz_fd_fini(void);

extern regex_t * re_include;
extern regex_t * re_exclude;

extern int _zz_mustwatch(char const *);
extern int _zz_iswatched(int);
extern void _zz_register(int);
extern void _zz_unregister(int);
extern long int _zz_getpos(int);
extern void _zz_setpos(int, long int);
extern void _zz_addpos(int, long int);
extern struct fuzz *_zz_getfuzz(int);

