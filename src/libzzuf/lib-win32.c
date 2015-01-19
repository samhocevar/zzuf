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
#if defined HAVE_READFILEEX
static BOOL (__stdcall *ORIG(ReadFileEx))(HANDLE, LPVOID, DWORD, LPDWORD,
    LPOVERLAPPED, LPOVERLAPPED_COMPLETION_ROUTINE);
#endif
#if defined HAVE_CREATEIOCOMPLETIONPORT
static HANDLE (__stdcall *ORIG(CreateIoCompletionPort))(HANDLE, HANDLE, ULONG_PTR, DWORD);
#endif
#if defined HAVE_GETQUEUEDCOMPLETIONSTATUS
static BOOL (__stdcall *ORIG(GetQueuedCompletionStatus))(HANDLE, LPDWORD, PULONG_PTR, LPOVERLAPPED *, DWORD);
#endif
#if defined HAVE_GETOVERLAPPEDRESULT
static BOOL (__stdcall *ORIG(GetOverlappedResult))(HANDLE, LPOVERLAPPED, LPDWORD, BOOL);
#endif
#if defined HAVE_CREATEFILEMAPPINGA
static HANDLE (__stdcall *ORIG(CreateFileMappingA))(HANDLE, LPSECURITY_ATTRIBUTES,
                                                   DWORD, DWORD, DWORD, LPCSTR);
#endif
#if defined HAVE_CREATEFILEMAPPINGW
static HANDLE (__stdcall *ORIG(CreateFileMappingW))(HANDLE, LPSECURITY_ATTRIBUTES,
                                                   DWORD, DWORD, DWORD, LPCWSTR);
#endif
#ifdef HAVE_MAPVIEWOFFILE
static LPVOID (__stdcall *ORIG(MapViewOfFile))(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
#endif
#if defined HAVE_CLOSEHANDLE
static BOOL (__stdcall *ORIG(CloseHandle))(HANDLE);
#endif
#if defined HAVE_ALLOCCONSOLE
static BOOL (__stdcall *ORIG(AllocConsole))();
#endif
#if defined HAVE_ATTACHCONSOLE
static BOOL (__stdcall *ORIG(AttachConsole))(DWORD dwProcessId);
#endif
#if defined HAVE_SETCONSOLEMODE
static BOOL (__stdcall *ORIG(SetConsoleMode))(HANDLE hConsoleHandle,
                                              DWORD dwMode);
#endif
#if defined HAVE_WRITECONSOLEOUTPUTA
static BOOL (__stdcall *ORIG(WriteConsoleOutputA))(HANDLE hConsoleOutput,
                 CONST CHAR_INFO *lpBuffer, COORD dwBufferSize,
                 COORD dwBufferCoord, PSMALL_RECT lpWriteRegion);
#endif
#if defined HAVE_WRITECONSOLEOUTPUTW
static BOOL (__stdcall *ORIG(WriteConsoleOutputW))(HANDLE hConsoleOutput,
                 CONST CHAR_INFO *lpBuffer, COORD dwBufferSize,
                 COORD dwBufferCoord, PSMALL_RECT lpWriteRegion);
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

    if (!g_libzzuf_ready || _zz_islocked(-1))
        return ret;
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

    if (!g_libzzuf_ready || _zz_islocked(-1))
        return ret;
    if (ret != INVALID_HANDLE_VALUE && dwCreationDisposition == OPEN_EXISTING
         && _zz_mustwatchw(lpFileName))
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
    debug("ReadFile(%#08x, %p, %#08x, %#08x, %p) = %s",
        hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped, (ret ? "TRUE" : "FALSE"));

    if (!must_fuzz_fd(hFile) /*|| !_zz_hostwatched(hFile)*/)
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

#if defined HAVE_READFILEEX
BOOL __stdcall NEW(ReadFileEx)(HANDLE hFile, LPVOID lpBuffer,
    DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped, LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    BOOL ret;

    ret = ORIG(ReadFileEx)(hFile, lpBuffer, nNumberOfBytesToRead,
        lpNumberOfBytesRead, lpOverlapped, lpCompletionRoutine);

    debug("ReadFileEx(%#08x, %p, %#08x, %p, %p, %p) = %s",
        hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped, lpCompletionRoutine, (ret ? "TRUE" : "FALSE"));

    if (!must_fuzz_fd(hFile) /*|| !_zz_hostwatched(hFile)*/)
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

#if defined HAVE_CREATEIOCOMPLETIONPORT
HANDLE __stdcall NEW(CreateIoCompletionPort)(HANDLE FileHandle, HANDLE ExistingCompletionPort, ULONG_PTR CompletionKey, DWORD NumberOfConcurrentThreads)
{
    HANDLE ret;

    ret = ORIG(CreateIoCompletionPort)(FileHandle, ExistingCompletionPort,
                                   CompletionKey, NumberOfConcurrentThreads);

    debug("GetQueuedCompletionStatus(0x%08x, 0x%08x, 0x%08x, %d) = 0x%08x",
          FileHandle, ExistingCompletionPort, CompletionKey,
          NumberOfConcurrentThreads, ret);

    if (!must_fuzz_fd(FileHandle) /*|| !_zz_hostwatched(FileHandle)*/)
        return ret;

    if (ret != NULL)
    {
        debug("handle %#08x is registered", ret);
        _zz_register(ret);
    }

    return ret;
}
#endif

#if defined HAVE_GETQUEUEDCOMPLETIONSTATUS
BOOL __stdcall NEW(GetQueuedCompletionStatus)(HANDLE CompletionPort, LPDWORD lpNumberOfBytes, PULONG_PTR lpCompletion, LPOVERLAPPED *lpOverlapped, DWORD dwMilliseconds)
{
    BOOL ret;

    ret = ORIG(GetQueuedCompletionStatus)(CompletionPort, lpNumberOfBytes, lpCompletion, lpOverlapped, dwMilliseconds);

    debug("GetQueuedCompletionStatus(0x%08x, { %d }, %p, %p, %d) = %s",
        CompletionPort, *lpNumberOfBytes, lpCompletion, lpOverlapped, dwMilliseconds, (ret ? "TRUE" : "FALSE"));

    return ret;
}
#endif

#if defined HAVE_GETOVERLAPPEDRESULT
BOOL __stdcall NEW(GetOverlappedResult)(HANDLE hFile, LPOVERLAPPED lpOverlapped, LPDWORD lpNumberOfBytesTransferred, BOOL bWait)
{
    BOOL ret;

    ret = ORIG(GetOverlappedResult)(hFile, lpOverlapped, lpNumberOfBytesTransferred, bWait);

    debug("GetOverlappedResult(0x%#08x, %p, %p, %s) = %s",
        hFile, lpOverlapped, lpNumberOfBytesTransferred, (bWait ? "TRUE" : "FALSE"), (ret ? "TRUE" : "FALSE"));

    return ret;
}
#endif

#if defined HAVE_CREATEFILEMAPPINGA
HANDLE __stdcall NEW(CreateFileMappingA)(HANDLE hFile, LPSECURITY_ATTRIBUTES lpAttributes,
            DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow,
            LPCSTR lpName)
{
    HANDLE ret;
    ret = ORIG(CreateFileMappingA)(hFile, lpAttributes,
        flProtect, dwMaximumSizeHigh, dwMaximumSizeLow,
        lpName);

    debug("CreateFileMappingA(%#08x, %#08x, %#08x, %#08x, %#08x, %s) = %#08x",
        hFile, lpAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName, ret);

    if (ret == NULL)
        return ret;

    if (!must_fuzz_fd(hFile) /*|| !_zz_hostwatched(hFile)*/ || _zz_islocked(-1))
        return ret;

    debug("handle %#08x is registered", ret);
    _zz_register(ret);

    return ret;
}
#endif

#if defined HAVE_CREATEFILEMAPPINGW
HANDLE __stdcall NEW(CreateFileMappingW)(HANDLE hFile, LPSECURITY_ATTRIBUTES lpAttributes,
            DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow,
            LPCWSTR lpName)
{
    HANDLE ret;
    ret = ORIG(CreateFileMappingW)(hFile, lpAttributes,
        flProtect, dwMaximumSizeHigh, dwMaximumSizeLow,
        lpName);

    debug("CreateFileMappingW(%#08x, %#08x, %#08x, %#08x, %#08x, %S) = %#08x",
        hFile, lpAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName, ret);

    if (ret == NULL)
        return ret;

    if (!must_fuzz_fd(hFile) /*|| !_zz_hostwatched(hFile)*/ || _zz_islocked(-1))
        return ret;

    debug("handle %#08x is registered", ret);
    _zz_register(ret);

    return ret;
}
#endif

#ifdef HAVE_MAPVIEWOFFILE
LPVOID __stdcall NEW(MapViewOfFile)(HANDLE hFileMappingObject, DWORD dwDesiredAccess,
    DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow,
    SIZE_T dwNumberOfBytesToMap)
{
    LPVOID ret;
    ret = ORIG(MapViewOfFile)(hFileMappingObject, dwDesiredAccess,
        dwFileOffsetHigh, dwFileOffsetLow,
        dwNumberOfBytesToMap);

    debug("MapViewOfFile(%#08x, %#08x, %#08x, %#08x, %#08x) = %p",
        hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap, ret);

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
    if (!g_libzzuf_ready || !_zz_iswatched(hObject) || _zz_islocked(hObject))
        return ret;
    _zz_unregister(hObject);
    return ret;
}
#endif

#if defined HAVE_ALLOCCONSOLE
BOOL __stdcall NEW(AllocConsole)()
{
    debug("AllocConsole()");
    return ORIG(AllocConsole)();
}
#endif

#if defined HAVE_ATTACHCONSOLE
BOOL __stdcall NEW(AttachConsole)(DWORD dwProcessId)
{
    debug("AttachConsole(%#08x)");
    return ORIG(AttachConsole)(dwProcessId);
}
#endif

#if defined HAVE_SETCONSOLEMODE
BOOL __stdcall NEW(SetConsoleMode)(HANDLE hConsoleHandle, DWORD dwMode)
{
    debug("SetConsoleMode(%#08x, %#08x)", (int)hConsoleHandle, dwMode);
    return ORIG(SetConsoleMode)(hConsoleHandle, dwMode);
}
#endif

#if defined HAVE_WRITECONSOLEOUTPUTA
BOOL __stdcall NEW(WriteConsoleOutputA)(HANDLE hConsoleOutput,
                               CONST CHAR_INFO *lpBuffer, COORD dwBufferSize,
                               COORD dwBufferCoord, PSMALL_RECT lpWriteRegion)
{
    debug("WriteConsoleOutputA(%#08x, %p, ...)", (int)hConsoleOutput, lpBuffer);
    return ORIG(WriteConsoleOutputA)(hConsoleOutput, lpBuffer, dwBufferSize,
                                     dwBufferCoord, lpWriteRegion);
}
#endif

#if defined HAVE_WRITECONSOLEOUTPUTW
BOOL __stdcall NEW(WriteConsoleOutputW)(HANDLE hConsoleOutput,
                               CONST CHAR_INFO *lpBuffer, COORD dwBufferSize,
                               COORD dwBufferCoord, PSMALL_RECT lpWriteRegion)
{
    debug("WriteConsoleOutputW(%#08x, %p, ...)", (int)hConsoleOutput, lpBuffer);
    return ORIG(WriteConsoleOutputW)(hConsoleOutput, lpBuffer, dwBufferSize,
                                     dwBufferCoord, lpWriteRegion);
}
#endif

/* Win32 function table */
#if defined HAVE_WINDOWS_H
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
#if defined HAVE_READFILEEX
    DIVERT(ReadFileEx),
#endif
#if defined HAVE_CREATEIOCOMPLETIONPORT
    DIVERT(CreateIoCompletionPort),
#endif
#if defined HAVE_GETQUEUEDCOMPLETIONSTATUS
    DIVERT(GetQueuedCompletionStatus),
#endif
#if defined HAVE_GETOVERLAPPEDRESULT
    DIVERT(GetOverlappedResult),
#endif
#if defined HAVE_CREATEFILEMAPPINGA
    DIVERT(CreateFileMappingA),
#endif
#if defined HAVE_CREATEFILEMAPPINGW
    DIVERT(CreateFileMappingW),
#endif
#ifdef HAVE_MAPVIEWOFFILE
    DIVERT(MapViewOfFile),
#endif

#if defined HAVE_ALLOCCONSOLE
    DIVERT(AllocConsole),
#endif
#if defined HAVE_ATTACHCONSOLE
    DIVERT(AttachConsole),
#endif
#if defined HAVE_SETCONSOLEMODE
    DIVERT(SetConsoleMode),
#endif
#if defined HAVE_WRITECONSOLEOUTPUTA
    DIVERT(WriteConsoleOutputA),
#endif
#if defined HAVE_WRITECONSOLEOUTPUTW
    DIVERT(WriteConsoleOutputW),
#endif

    DIVERT_END
};
#endif

