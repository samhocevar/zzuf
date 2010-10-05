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
static HANDLE (__stdcall *ORIG(CreateFileA))(LPCTSTR, DWORD, DWORD,
                                             LPSECURITY_ATTRIBUTES,
                                             DWORD, DWORD, HANDLE);
#endif
#if defined HAVE_CREATEFILEA
static HANDLE (__stdcall *ORIG(CreateFileW))(LPCWSTR, DWORD, DWORD,
                                             LPSECURITY_ATTRIBUTES,
                                             DWORD, DWORD, HANDLE);
#endif
#if defined HAVE_READFILE
static BOOL (__stdcall *ORIG(ReadFile))(HANDLE, LPVOID, DWORD, LPDWORD,
                                        LPOVERLAPPED);
#endif
#if defined HAVE_CLOSEHANDLE
static BOOL (__stdcall *ORIG(CloseHandle))(HANDLE);
#endif

/*
 * CreateFileA, CreateFileW
 */

#if defined HAVE_CREATEFILEA
HANDLE __stdcall NEW(CreateFileA)(LPCTSTR lpFileName, DWORD dwDesiredAccess,
           DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
           DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes,
           HANDLE hTemplateFile)
{
    HANDLE ret;
    ret = ORIG(CreateFileA)(lpFileName, dwDesiredAccess, dwShareMode,
                            lpSecurityAttributes, dwCreationDisposition,
                            dwFlagsAndAttributes, hTemplateFile);
    debug("%s(\"%s\", %x, %x, ..., %x, %x, ...) = [%i]",
          __func__, lpFileName, dwDesiredAccess, dwShareMode,
          dwCreationDisposition, dwFlagsAndAttributes, (int)ret); \
    return ret;
}
#endif

#if defined HAVE_CREATEFILEW
HANDLE __stdcall NEW(CreateFileW)(LPCWSTR lpFileName, DWORD dwDesiredAccess,
           DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
           DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes,
           HANDLE hTemplateFile)
{
    fprintf(stderr, "CreateFileW(?)\n");
    return ORIG(CreateFileW)(lpFileName, dwDesiredAccess, dwShareMode,
                             lpSecurityAttributes, dwCreationDisposition,
                             dwFlagsAndAttributes, hTemplateFile);
}
#endif

/*
 * ReadFile
 */

#if defined HAVE_READFILE
BOOL __stdcall NEW(ReadFile)(HANDLE hFile, LPVOID lpBuffer,
           DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead,
           LPOVERLAPPED lpOverlapped)
{
    fprintf(stderr, "ReadFile(%i)\n", nNumberOfBytesToRead);
    return ORIG(ReadFile)(hFile, lpBuffer, nNumberOfBytesToRead,
                          lpNumberOfBytesRead, lpOverlapped);
}
#endif

/*
 * CloseHandle
 */

#if defined HAVE_CLOSEHANDLE
BOOL __stdcall NEW(CloseHandle)(HANDLE hObject)
{
    fprintf(stderr, "CloseHandle(%i)\n", hObject);
    return ORIG(CloseHandle)(hObject);
}
#endif

/* Win32 function table */
#if defined _WIN32
#   define DIVERT(x) { "kernel32.dll", #x, \
                      (void **)&x##_orig, (void *)x##_new }
#   define DIVERT_END { NULL, NULL, NULL, NULL }

zzuf_table_t table_win32[] =
{
#if defined HAVE_CLOSEHANDLE
    DIVERT(CloseHandle),
#endif
#if defined HAVE_CREATEFILEA
    DIVERT(CreateFileA),
#endif
#if defined HAVE_CREATEFILEW
    DIVERT(CreateFileW),
#endif
#if defined HAVE_READFILE
    DIVERT(ReadFile),
#endif
    DIVERT_END
};
#endif

