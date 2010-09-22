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

#if defined HAVE_WINDOWS_H
#   include <windows.h>
#endif

#include <stdio.h>

#include "common.h"
#include "libzzuf.h"
#include "lib-load.h"
#include "debug.h"
#include "fuzz.h"
#include "fd.h"

/* Kernel functions that we divert */
#if defined HAVE_CREATEFILE
static HANDLE (*ORIG(CreateFileA))(LPCTSTR lpFileName, DWORD dwDesiredAccess,
           DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
           DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes,
           HANDLE hTemplateFile);
#endif

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

/* Win32 function table */
zzuf_table_t table_win32[] =
{
#if defined HAVE_CREATEFILE
    DIVERT(CreateFileA),
#endif
    DIVERT_END
};

