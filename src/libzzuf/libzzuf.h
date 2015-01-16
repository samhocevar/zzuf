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
 *  libzzuf.h: preloaded wrapper library
 */

#include "fd.h"

/* Internal variables */
extern int _zz_ready;
extern int _zz_disabled;
extern int _zz_debuglevel;
extern int _zz_debugfd;
extern int _zz_signal;
extern uint64_t _zz_memory;
extern int _zz_network;
extern int _zz_autoinc;

/* Library initialisation shit */
#if defined __GNUC__
extern void _zz_init(void) __attribute__((constructor));
extern void _zz_fini(void) __attribute__((destructor));
#elif defined HAVE_PRAGMA_INIT
#   pragma INIT "_zz_init"
#   pragma FINI "_zz_fini"
#endif

/* This function is needed to initialise memory functions */
extern void _zz_mem_init(void);

/* This function lets us know where the end of a file is. */
extern size_t _zz_bytes_until_eof(int fd, size_t offset);

#ifdef _WIN32
#   include <windows.h>
extern CRITICAL_SECTION _zz_pipe_cs;
#endif

static inline int must_fuzz_fd(int fd)
{
    return _zz_ready && _zz_iswatched(fd)
            && !_zz_islocked(fd) && _zz_isactive(fd);
}

