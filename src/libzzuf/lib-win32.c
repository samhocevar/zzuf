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
#if defined HAVE_IO_H
#   include <io.h>
#endif

#include "common.h"
#include "libzzuf.h"
#include "lib-load.h"
#include "debug.h"
#include "fuzz.h"
#include "fd.h"

/* Kernel functions that we divert */
#if defined HAVE_CREATEFILEA
static HANDLE (__stdcall *ORIG(CreateFileA))(LPCSTR, DWORD, DWORD,
                                             LPSECURITY_ATTRIBUTES,
                                             DWORD, DWORD, HANDLE);
#endif
#if defined HAVE_CREATEFILEW
static HANDLE (__stdcall *ORIG(CreateFileW))(LPCWSTR, DWORD, DWORD,
                                             LPSECURITY_ATTRIBUTES,
                                             DWORD, DWORD, HANDLE);
#endif
#if defined HAVE_REOPENFILE
static HANDLE (__stdcall *ORIG(ReOpenFile))(HANDLE, DWORD,
                                            DWORD, DWORD);
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
HANDLE __stdcall NEW(CreateFileA)(LPCSTR lpFileName, DWORD dwDesiredAccess,
           DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
           DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes,
           HANDLE hTemplateFile)
{
    HANDLE ret;

    ret = ORIG(CreateFileA)(lpFileName, dwDesiredAccess, dwShareMode,
                            lpSecurityAttributes, dwCreationDisposition,
                            dwFlagsAndAttributes, hTemplateFile);
    debug("CreateFileA(\"%s\", 0x%x, 0x%x, {...}, 0x%x, 0x%x, {...}) = %#08x",
          lpFileName, dwDesiredAccess, dwShareMode, dwCreationDisposition,
          dwFlagsAndAttributes, (int)ret);

    if(!_zz_ready || _zz_islocked(-1)) return ret;
    if (ret != INVALID_HANDLE_VALUE && dwCreationDisposition == OPEN_EXISTING && _zz_mustwatch(lpFileName))
    {
        _zz_register(ret);
    }

    return ret;
}
#endif

#if defined HAVE_CREATEFILEW
HANDLE __stdcall NEW(CreateFileW)(LPCWSTR lpFileName, DWORD dwDesiredAccess,
           DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
           DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes,
           HANDLE hTemplateFile)
{
    HANDLE ret;
    ret = ORIG(CreateFileW)(lpFileName, dwDesiredAccess, dwShareMode,
                            lpSecurityAttributes, dwCreationDisposition,
                            dwFlagsAndAttributes, hTemplateFile);
    debug("CreateFileW(\"%S\", 0x%x, 0x%x, {...}, 0x%x, 0x%x, {...}) = %#08x",
          lpFileName, dwDesiredAccess, dwShareMode, dwCreationDisposition,
          dwFlagsAndAttributes, (int)ret);

    if(!_zz_ready || _zz_islocked(-1)) return ret;
    if (ret != INVALID_HANDLE_VALUE && dwCreationDisposition == OPEN_EXISTING && _zz_mustwatch(lpFileName))
    {
        debug("handle %#08x is registered", ret);
        _zz_register(ret);
    }


    return ret;
}
#endif

#if defined HAVE_REOPENFILE
HANDLE __stdcall NEW(ReOpenFile)(HANDLE hOriginalFile, DWORD dwDesiredAccess,
                                 DWORD dwShareMode, DWORD dwFlags)
{
    HANDLE ret;
    ret = ORIG(ReOpenFile)(hOriginalFile, dwDesiredAccess,
                           dwShareMode, dwFlags);
    debug("ReOpenFile(%#08x, 0x%x, 0x%x, 0x%x) = %#08x", (int)hOriginalFile,
          dwDesiredAccess, dwShareMode, dwFlags, (int)ret);
    return ret;
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
    BOOL ret;
    ret = ORIG(ReadFile)(hFile, lpBuffer, nNumberOfBytesToRead,
                          lpNumberOfBytesRead, lpOverlapped);
    debug("ReadFile(%#08x, %#08x, %#08x, %#08x, %#08x) = %s",
        hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped, (ret ? "TRUE" : "FALSE"));

    if (!_zz_ready || !_zz_iswatched(hFile) /*|| !_zz_hostwatched(hFile)*/ || _zz_islocked(hFile) || !_zz_isactive(hFile))
        return ret;

    if (ret)
    {
        DWORD bytes_read = lpNumberOfBytesRead ? *lpNumberOfBytesRead : nNumberOfBytesToRead;
        debug("fuzzing file %#08x\n", hFile);
        _zz_fuzz(hFile, lpBuffer, bytes_read);
        _zz_addpos(hFile, bytes_read);
    }
    return ret;
}
#endif

/*
 * CloseHandle
 */

#if defined HAVE_CLOSEHANDLE
BOOL __stdcall NEW(CloseHandle)(HANDLE hObject)
{
    BOOL ret;

    /* TODO: Check if fuzzed application tries to close our debug channel */

    ret = ORIG(CloseHandle)(hObject);
    debug("CloseHandle(%#08x) = %s", (int)hObject, (ret ? "TRUE" : "FALSE"));
    if (!_zz_ready || !_zz_iswatched(hObject) || _zz_islocked(hObject))
        return ret;
    _zz_unregister(hObject);
    return ret;
}
#endif

/* Win32 function table */
#if defined HAVE_WINDOWS_H
#   define DIVERT(x) { "kernel32.dll", #x, \
                      (void **)&x##_orig, (void *)x##_new }
#   define DIVERT_END { NULL, NULL, NULL, NULL }

zzuf_table_t table_win32[] =
{
    DIVERT(CloseHandle),
    DIVERT(CreateFileA),
    DIVERT(CreateFileW),
    DIVERT(ReadFile),
    DIVERT_END
};
#endif

