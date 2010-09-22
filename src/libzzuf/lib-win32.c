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
 *  load-win32.c: loaded Win32 functions
 */

#include "config.h"

#if defined HAVE_STDINT_H
#   include <stdint.h>
#elif defined HAVE_INTTYPES_H
#   include <inttypes.h>
#endif

#include <stdio.h>

#if defined HAVE_WINDOWS_H
#   include <windows.h>
#endif

#include "common.h"
#include "libzzuf.h"
#include "lib-load.h"
#include "debug.h"
#include "fuzz.h"
#include "fd.h"

/* Kernel functions that we divert */
#if defined HAVE_CREATEFILEA
static HANDLE (*ORIG(CreateFileA))(LPCTSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES,
                                   DWORD, DWORD, HANDLE);
#endif

#if defined HAVE_CREATEFILEA
static HANDLE (*ORIG(CreateFileW))(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES,
                                   DWORD, DWORD, HANDLE);
#endif

#if defined HAVE_CREATEFILEA
HANDLE NEW(CreateFileA)(LPCTSTR lpFileName, DWORD dwDesiredAccess,
           DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
           DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes,
           HANDLE hTemplateFile)
{
    fprintf(stderr, "CreateFileA diverted!\n");
    return ORIG(CreateFileA)(lpFileName, dwDesiredAccess, dwShareMode,
                             lpSecurityAttributes, dwCreationDisposition,
                             dwFlagsAndAttributes, hTemplateFile);
}
#endif

#if defined HAVE_CREATEFILEW
HANDLE NEW(CreateFileW)(LPCWSTR lpFileName, DWORD dwDesiredAccess,
           DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
           DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes,
           HANDLE hTemplateFile)
{
    fprintf(stderr, "CreateFileW diverted!\n");
    return ORIG(CreateFileW)(lpFileName, dwDesiredAccess, dwShareMode,
                             lpSecurityAttributes, dwCreationDisposition,
                             dwFlagsAndAttributes, hTemplateFile);
}
#endif

/* Win32 function table */
#if defined _WIN32
zzuf_table_t table_win32[] =
{
#if defined HAVE_CREATEFILEA
    DIVERT(CreateFileA),
#endif
#if defined HAVE_CREATEFILEW
    DIVERT(CreateFileW),
#endif
    DIVERT_END
};
#endif

