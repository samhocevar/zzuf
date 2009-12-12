/*
 *  zzuf - general purpose fuzzer
 *  Copyright (c) 2002, 2007-2009 Sam Hocevar <sam@hocevar.net>
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
 *  myfork.c: launcher
 */

#include "config.h"

#define _INCLUDE_POSIX_SOURCE /* for STDERR_FILENO on HP-UX */

#if defined HAVE_STDINT_H
#   include <stdint.h>
#elif defined HAVE_INTTYPES_H
#   include <inttypes.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#if defined HAVE_UNISTD_H
#   include <unistd.h>
#endif
#if defined HAVE_WINDOWS_H
#   include <windows.h>
#   include <imagehlp.h>
#   include <tlhelp32.h>
#endif
#include <string.h>
#include <fcntl.h> /* for O_BINARY */

#include "common.h"
#include "opts.h"
#include "random.h"
#include "fd.h"
#include "fuzz.h"
#include "myfork.h"
#include "md5.h"
#include "timer.h"

static int run_process(struct opts *, int[][2]);

#if defined HAVE_WINDOWS_H
static int dll_inject(void *, void *);
static intptr_t get_base_address(DWORD);
static intptr_t get_entry_point_offset(char const *);
#endif

#if defined HAVE_WINDOWS_H
static inline void addcpy(void *buf, void *x)
{
    memcpy(buf, &x, 4);
}
#endif

int myfork(struct child *child, struct opts *opts)
{
    int pipes[3][2];
    pid_t pid;
    int i;

    /* Prepare communication pipe */
    for(i = 0; i < 3; i++)
    {
        int ret;
#if defined HAVE_PIPE
        ret = pipe(pipes[i]);
#elif defined HAVE__PIPE
        ret = _pipe(pipes[i], 512, _O_BINARY | O_NOINHERIT);
#endif
        if(ret < 0)
        {
            perror("pipe");
            return -1;
        }
    }

    pid = run_process(opts, pipes);
    if(pid < 0)
    {
        /* FIXME: close pipes */
        fprintf(stderr, "error launching `%s'\n", opts->newargv[0]);
        return -1;
    }

    child->pid = pid;
    for(i = 0; i < 3; i++)
    {
        close(pipes[i][1]);
        child->fd[i] = pipes[i][0];
    }

    return 0;
}

#if !defined HAVE_SETENV
static void setenv(char const *name, char const *value, int overwrite)
{
    char *str;

    if(!overwrite && getenv(name))
        return;

    str = malloc(strlen(name) + 1 + strlen(value) + 1);
    sprintf(str, "%s=%s", name, value);
    putenv(str);
}
#endif

static int run_process(struct opts *opts, int pipes[][2])
{
    char buf[64];
#if defined HAVE_FORK
    static int const files[] = { DEBUG_FILENO, STDERR_FILENO, STDOUT_FILENO };
    char *libpath, *tmp;
    int pid, j, len = strlen(opts->oldargv[0]);
#   if defined __APPLE__
#       define EXTRAINFO ""
#       define PRELOAD "DYLD_INSERT_LIBRARIES"
    setenv("DYLD_FORCE_FLAT_NAMESPACE", "1", 1);
#   elif defined __osf__
#       define EXTRAINFO ":DEFAULT"
#       define PRELOAD "_RLD_LIST"
#   else
#       define EXTRAINFO ""
#       define PRELOAD "LD_PRELOAD"
#   endif
#elif HAVE_WINDOWS_H
    PROCESS_INFORMATION pinfo;
    STARTUPINFO sinfo;
    HANDLE pid;
    void *epaddr;
    int ret;
#endif

#if defined HAVE_FORK
    /* Fork and launch child */
    pid = fork();
    if(pid < -1)
        perror("fork");
    if(pid != 0)
        return pid;

    /* We loop in reverse order so that files[0] is done last,
     * just in case one of the other dup2()ed fds had the value */
    for(j = 3; j--; )
    {
        close(pipes[j][0]);
        if(pipes[j][1] != files[j])
        {
            dup2(pipes[j][1], files[j]);
            close(pipes[j][1]);
        }
    }
#endif

#if defined HAVE_SETRLIMIT && defined ZZUF_RLIMIT_MEM
    if(opts->maxmem >= 0)
    {
        struct rlimit rlim;
        rlim.rlim_cur = opts->maxmem * 1000000;
        rlim.rlim_max = opts->maxmem * 1000000;
        setrlimit(ZZUF_RLIMIT_MEM, &rlim);
    }
#endif

#if defined HAVE_SETRLIMIT && defined ZZUF_RLIMIT_CPU
    if(opts->maxcpu >= 0)
    {
        struct rlimit rlim;
        rlim.rlim_cur = opts->maxcpu;
        rlim.rlim_max = opts->maxcpu + 5;
        setrlimit(ZZUF_RLIMIT_CPU, &rlim);
    }
#endif

    /* Set environment variables */
    sprintf(buf, "%i", opts->seed);
    setenv("ZZUF_SEED", buf, 1);
    sprintf(buf, "%g", opts->minratio);
    setenv("ZZUF_MINRATIO", buf, 1);
    sprintf(buf, "%g", opts->maxratio);
    setenv("ZZUF_MAXRATIO", buf, 1);

#if defined HAVE_FORK
    /* Make sure there is space for everything we might do. */
    libpath = malloc(len + strlen(LIBDIR "/" LT_OBJDIR SONAME EXTRAINFO) + 1);
    strcpy(libpath, opts->oldargv[0]);

    /* If the binary name contains a '/', we look for a libzzuf in the
     * same directory. Otherwise, we only look into the system directory
     * to avoid shared library attacks. Write the result in libpath. */
    tmp = strrchr(libpath, '/');
    if(tmp)
    {
        strcpy(tmp + 1, LT_OBJDIR SONAME);
        if(access(libpath, R_OK) < 0)
            strcpy(libpath, LIBDIR "/" SONAME);
    }
    else
        strcpy(libpath, LIBDIR "/" SONAME);

    /* OSF1 only */
    strcat(libpath, EXTRAINFO);

    /* Do not clobber previous LD_PRELOAD values */
    tmp = getenv(PRELOAD);
    if(tmp && *tmp)
    {
        char *bigbuf = malloc(strlen(tmp) + strlen(libpath) + 2);
        sprintf(bigbuf, "%s:%s", tmp, libpath);
        free(libpath);
        libpath = bigbuf;
    }

    setenv(PRELOAD, libpath, 1);
    free(libpath);

    if(execvp(opts->newargv[0], opts->newargv))
    {
        perror(opts->newargv[0]);
        exit(EXIT_FAILURE);
    }

    exit(EXIT_SUCCESS);
    /* no return */
    return 0;
#elif HAVE_WINDOWS_H
    pid = GetCurrentProcess();

    memset(&sinfo, 0, sizeof(sinfo));
    sinfo.cb = sizeof(sinfo);
    DuplicateHandle(pid, (HANDLE)_get_osfhandle(pipes[0][1]), pid,
        /* FIXME */ &sinfo.hStdInput, 0, TRUE, DUPLICATE_SAME_ACCESS);
    DuplicateHandle(pid, (HANDLE)_get_osfhandle(pipes[1][1]), pid,
                    &sinfo.hStdError, 0, TRUE, DUPLICATE_SAME_ACCESS);
    DuplicateHandle(pid, (HANDLE)_get_osfhandle(pipes[2][1]), pid,
                    &sinfo.hStdOutput, 0, TRUE, DUPLICATE_SAME_ACCESS);
    sinfo.dwFlags = STARTF_USESTDHANDLES;
    ret = CreateProcess(NULL, opts->newargv[0], NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &sinfo, &pinfo);
    if(!ret)
        return -1;

    /* Get the child process's entry point address */
    epaddr = (void *)(get_base_address(pinfo.dwProcessId)
                       + get_entry_point_offset(opts->newargv[0]));
    if(!epaddr)
        return -1;

    /* Insert the replacement code */
    ret = dll_inject(pinfo.hProcess, epaddr);
    if(ret < 0)
    {
        TerminateProcess(pinfo.hProcess, -1);
        return -1;
    }

    ret = ResumeThread(pinfo.hThread);
    if(ret < 0)
    {
        TerminateProcess(pinfo.hProcess, -1);
        return -1;
    }

    return (long int)pinfo.hProcess;
#endif
}

#if defined HAVE_WINDOWS_H
static int dll_inject(void *process, void *epaddr)
{
    uint8_t code1[] =                  /* LIBZZUF: */
                      "libzzuf.dll\0"
                                       /* OLDEP: */
                      "_______"
                                       /* START: */
                      "\xb8____"       /* mov eax,<libzzuf.dll> */
                      "\x50"           /* push eax */
                      "\xb8____"       /* mov eax,<LoadLibraryA> */
                      "\xff\xd0"       /* call eax */
                      "\xb8\0\0\0\0"   /* mov eax,0 */
                      "\x50"           /* push eax */
                      "\xb8\x07\0\0\0" /* mov eax,7 */
                      "\x50"           /* push eax */
                      "\xb8____"       /* mov eax,<OLDEP> */
                      "\x50"           /* push eax */
                      "\xb8____"       /* mov eax,<NEWEP> */
                      "\x50"           /* push eax */
                      "\xb8____"       /* mov eax,<GetCurrentProcess> */
                      "\xff\xd0"       /* call eax */
                      "\x50"           /* push eax */
                      "\xb8____"       /* mov eax,<WriteProcessMemory> */
                      "\xff\xd0"       /* call eax */
                      "\xb8____"       /* mov eax,<NEWEP> */
                      "\xff\xe0";      /* jmp eax */
    uint8_t code2[] =                  /* NEWEP: */
                      "\xb8____"       /* mov eax,<START> */
                      "\xff\xe0";      /* jmp eax */
    void *lib;
    uint8_t *loaderaddr;
    DWORD tmp;

    /* Backup the old entry-point code */
    ReadProcessMemory(process, epaddr, code1 + 0x0c, 7, &tmp);
    if(tmp != 7)
        return -1;

    /* Copy the first shell code to a freshly allocated memory area. */
    loaderaddr = VirtualAllocEx(process, NULL, sizeof(code1), MEM_COMMIT,
                                PAGE_EXECUTE_READWRITE);
    if(!loaderaddr)
        return -1;

    lib = LoadLibrary("kernel32.dll");
    if(!lib)
        return -1;

    addcpy(code1 + 0x14, loaderaddr + 0x00); /* offset for dll string */
    addcpy(code1 + 0x1a, GetProcAddress(lib, "LoadLibraryA"));
    addcpy(code1 + 0x2d, loaderaddr + 0x0c);
    addcpy(code1 + 0x33, epaddr);
    addcpy(code1 + 0x39, GetProcAddress(lib, "GetCurrentProcess"));
    addcpy(code1 + 0x41, GetProcAddress(lib, "WriteProcessMemory"));
    addcpy(code1 + 0x48, epaddr);
    FreeLibrary(lib);

    WriteProcessMemory(process, loaderaddr, code1, sizeof(code1), &tmp);
    if(tmp != sizeof(code1))
        return -1;

    /* Copy the second shell code where the old entry point was. */
    addcpy(code2 + 0x01, loaderaddr + 12 + 7);
    WriteProcessMemory(process, epaddr, code2, 7, &tmp);
    if(tmp != 7)
        return -1;

    return 0;
}

/* Find the process's base address once it is loaded in memory (the header
 * information is unreliable because of Vista's ASLR). */
static intptr_t get_base_address(DWORD pid)
{
    MODULEENTRY32 entry;
    intptr_t ret = 0;
    void *list;
    int k;

    list = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    entry.dwSize = sizeof(entry);
    for(k = Module32First(list, &entry); k; k = Module32Next(list, &entry))
    {
        /* FIXME: how do we select the correct module? */
        ret = (intptr_t)entry.modBaseAddr;
    }
    CloseHandle(list);

    return ret;
}

/* Find the process's entry point address offset. The information is in
 * the file's PE header. */
static intptr_t get_entry_point_offset(char const *name)
{
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS nt;
    intptr_t ret = 0;
    void *file, *map, *base;

    file = CreateFile(name, GENERIC_READ, FILE_SHARE_READ,
                      NULL, OPEN_EXISTING, 0, NULL);
    if(file == INVALID_HANDLE_VALUE)
        return ret;

    map = CreateFileMapping(file, NULL, PAGE_READONLY, 0, 0, NULL);
    if(!map)
    {
        CloseHandle(file);
        return ret;
    }

    base = MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0);
    if(!base)
    {
        CloseHandle(map);
        CloseHandle(file);
        return ret;
    }

    /* Sanity checks */
    dos = (PIMAGE_DOS_HEADER)base;
    nt = (PIMAGE_NT_HEADERS)((char *)base + dos->e_lfanew);
    if(dos->e_magic == IMAGE_DOS_SIGNATURE /* 0x5A4D */
      && nt->Signature == IMAGE_NT_SIGNATURE /* 0x00004550 */
      && nt->FileHeader.Machine == IMAGE_FILE_MACHINE_I386
      && nt->OptionalHeader.Magic == 0x10b /* IMAGE_NT_OPTIONAL_HDR32_MAGIC */)
    {
        ret = (intptr_t)nt->OptionalHeader.AddressOfEntryPoint;
    }

    UnmapViewOfFile(base);
    CloseHandle(map);
    CloseHandle(file);

    return ret;
}
#endif

