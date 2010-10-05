/*
 *  zzuf - general purpose fuzzer
 *  Copyright (c) 2002-2010 Sam Hocevar <sam@hocevar.net>
 *                All Rights Reserved
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
#if defined HAVE_IO_H
#   include <io.h>
#endif
#include <string.h>
#include <fcntl.h> /* for O_BINARY */
#if defined HAVE_SYS_RESOURCE_H
#   include <sys/resource.h> /* for RLIMIT_AS */
#endif

#include "common.h"
#include "opts.h"
#include "random.h"
#include "fd.h"
#include "fuzz.h"
#include "myfork.h"
#include "md5.h"
#include "timer.h"

/* Handle old libtool versions */
#if !defined LT_OBJDIR
#   define LT_OBJDIR ".libs/"
#endif

#if defined RLIMIT_AS
#   define ZZUF_RLIMIT_MEM RLIMIT_AS
#elif defined RLIMIT_VMEM
#   define ZZUF_RLIMIT_MEM RLIMIT_VMEM
#elif defined RLIMIT_DATA
#   define ZZUF_RLIMIT_MEM RLIMIT_DATA
#else
#   undef ZZUF_RLIMIT_MEM
#endif

#if defined RLIMIT_CPU
#   define ZZUF_RLIMIT_CPU RLIMIT_CPU
#else
#   undef ZZUF_RLIMIT_CPU
#endif

static int run_process(struct child *child, struct opts *, int[][2]);

#if defined HAVE_WINDOWS_H
#   define PARENT_FD(x) ((x) ? 0 : 1)
#   define CHILD_FD(x) ((x) ? 1 : 0)
#else
#   define PARENT_FD(x) 0
#   define CHILD_FD(x) 1
#endif

#if defined HAVE_WINDOWS_H
static void rep32(uint8_t *buf, void *addr);
static int dll_inject(PROCESS_INFORMATION *, char const *);
static intptr_t get_proc_address(void *, DWORD, char const *);
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
        int tmp;
        /* The pipe is created with NOINHERIT otherwise both parts are
         * inherited. We then duplicate the part we want. */
        ret = _pipe(pipes[i], 512, _O_BINARY | O_NOINHERIT);
        tmp = _dup(pipes[i][CHILD_FD(i)]);
        close(pipes[i][CHILD_FD(i)]);
        pipes[i][CHILD_FD(i)] = tmp;
#endif
        if(ret < 0)
        {
            perror("pipe");
            return -1;
        }
    }

    pid = run_process(child, opts, pipes);
    if(pid < 0)
    {
        /* FIXME: close pipes */
        fprintf(stderr, "error launching `%s'\n", child->newargv[0]);
        return -1;
    }

    child->pid = pid;
    for(i = 0; i < 3; i++)
    {
        close(pipes[i][CHILD_FD(i)]);
        child->fd[i] = pipes[i][PARENT_FD(i)];
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

static int run_process(struct child *child, struct opts *opts, int pipes[][2])
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
#   elif defined __sun && defined __i386
#       define EXTRAINFO ""
#       define PRELOAD "LD_PRELOAD_32"
#   else
#       define EXTRAINFO ""
#       define PRELOAD "LD_PRELOAD"
#   endif
#elif HAVE_WINDOWS_H
    PROCESS_INFORMATION pinfo;
    STARTUPINFO sinfo;
    HANDLE pid;
    char *cmdline;
    int i, ret, len;
#endif

#if defined HAVE_FORK
    /* Fork and launch child */
    pid = fork();
    if(pid < 0)
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
        rlim.rlim_cur = opts->maxmem * 1048576;
        rlim.rlim_max = opts->maxmem * 1048576;
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

    /* Only preload the library in preload mode */
    if (opts->opmode == OPMODE_PRELOAD)
        setenv(PRELOAD, libpath, 1);
    free(libpath);

    if(execvp(child->newargv[0], child->newargv))
    {
        perror(child->newargv[0]);
        exit(EXIT_FAILURE);
    }

    exit(EXIT_SUCCESS);
    /* no return */
    return 0;
#elif HAVE_WINDOWS_H
    pid = GetCurrentProcess();

    /* Inherit standard handles */
    memset(&sinfo, 0, sizeof(sinfo));
    sinfo.cb = sizeof(sinfo);
    sinfo.hStdInput = (HANDLE)_get_osfhandle(pipes[0][CHILD_FD(0)]);
    sinfo.hStdOutput = (HANDLE)_get_osfhandle(pipes[1][CHILD_FD(1)]);
    sinfo.hStdError = (HANDLE)_get_osfhandle(pipes[2][CHILD_FD(2)]);
    sinfo.dwFlags = STARTF_USESTDHANDLES;

    /* Build the commandline */
    for (i = 0, len = 0; child->newargv[i]; i++)
        len += strlen(child->newargv[i]) + 1;
    cmdline = malloc(len);
    for (i = 0, len = 0; child->newargv[i]; i++)
    {
        strcpy(cmdline + len, child->newargv[i]);
        len += strlen(child->newargv[i]) + 1;
        cmdline[len - 1] = ' ';
    }
    cmdline[len - 1] = '\0';

    /* Create the process in suspended state */
    ret = CreateProcess(child->newargv[0], cmdline, NULL, NULL, TRUE,
                        CREATE_SUSPENDED, NULL, NULL, &sinfo, &pinfo);
    free(cmdline);

    if (!ret)
        return -1;

    /* Insert the replacement code */
    ret = dll_inject(&pinfo, SONAME);
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
static void rep32(uint8_t *buf, void *addr)
{
    while(buf++)
        if (memcmp(buf, "____", 4) == 0)
        {
            memcpy(buf, &addr, 4);
            return;
        }
}

static int dll_inject(PROCESS_INFORMATION *pinfo, char const *lib)
{
    static uint8_t const loader[] =
        /* Load the injected DLL into memory */
        "\xb8____"       /* mov %eax, <library_name_address> */
        "\x50"           /* push %eax */
        "\xb8____"       /* mov %eax, <LoadLibraryA> */
        "\xff\xd0"       /* call %eax */
        /* Restore the clobbered entry point code using our backup */
        "\xb8\0\0\0\0"   /* mov %eax,0 */
        "\x50"           /* push %eax */
        "\xb8____"       /* mov %eax, <jumper_length> */
        "\x50"           /* push %eax */
        "\xb8____"       /* mov %eax, <backuped_entry_point_address> */
        "\x50"           /* push %eax */
        "\xb8____"       /* mov %eax, <original_entry_point_address> */
        "\x50"           /* push %eax */
        "\xb8____"       /* mov %eax, <GetCurrentProcess> */
        "\xff\xd0"       /* call %eax */
        "\x50"           /* push %eax */
        "\xb8____"       /* mov %eax, <WriteProcessMemory> */
        "\xff\xd0"       /* call %eax */
        /* Jump to the original entry point */
        "\xb8____"       /* mov %eax, <original_entry_point_address> */
        "\xff\xe0";      /* jmp %eax */

    static uint8_t const waiter[] =
        "\xeb\xfe";      /* jmp <current> */

    static uint8_t const jumper[] =
        /* Jump to the injected loader */
        "\xb8____"       /* mov eax, <loader_address> */
        "\xff\xe0";      /* jmp eax */

    CONTEXT ctx;
    void *process = pinfo->hProcess;
    void *thread = pinfo->hThread;
    void *epaddr;
    DWORD pid = pinfo->dwProcessId;

    /* code:
     * +---------------+--------------------+--------------+-------------+
     * |     loader    | entry point backup | library name |   jumper    |
     * |  len(loader)  |    len(jumper)     |   len(lib)   | len(jumper) |
     * +---------------+--------------------+--------------+-------------+ */
    uint8_t code[1024];

    uint8_t *loaderaddr;
    size_t liblen, loaderlen, waiterlen, jumperlen;
    DWORD tmp;

    liblen = strlen(lib) + 1;
    loaderlen = sizeof(loader) - 1;
    waiterlen = sizeof(waiter) - 1;
    jumperlen = sizeof(jumper) - 1;
    if (loaderlen + jumperlen + liblen > 1024)
        return -1;

    /* Allocate memory in the child for our injected code */
    loaderaddr = VirtualAllocEx(process, NULL, loaderlen + jumperlen + liblen,
                                MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if(!loaderaddr)
        return -1;

    /* Create the first shellcode (jumper).
     *
     * The jumper's job is simply to jump at the second shellcode's location.
     * It is written at the original entry point's location, which will in
     * turn be restored by the second shellcode.
     */
    memcpy(code + loaderlen + jumperlen + liblen, jumper, jumperlen);
    rep32(code + loaderlen + jumperlen + liblen, loaderaddr);

    /* Create the second shellcode (loader, backuped entry point, and library
     * name).
     *
     * The loader's job is to load the library by calling LoadLibraryA(),
     * restore the original entry point using the backup copy, and jump
     * back to the original entry point as if the process had just started.
     *
     * The second shellcode is written at a freshly allocated memory location.
     */
    memcpy(code, loader, loaderlen);
    memcpy(code + loaderlen + jumperlen, lib, liblen);

    /* Find the entry point address. It's simply in EAX. */
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(thread, &ctx);
    epaddr = (void *)(uintptr_t)ctx.Eax;

    /* Backup the old entry point code */
    ReadProcessMemory(process, epaddr, code + loaderlen, jumperlen, &tmp);
    if(tmp != jumperlen)
        return -1;

    /* Replace the entry point code with a short jump to self, then resume
     * the thread. This is necessary for CreateToolhelp32Snapshot() to
     * work. */
    WriteProcessMemory(process, epaddr, waiter, waiterlen, &tmp);
    if(tmp != waiterlen)
        return -1;
    FlushInstructionCache(process, epaddr, waiterlen);
    ResumeThread(thread);

    /* Wait until the entry point is reached */
    for (tmp = 0; tmp < 100; tmp++)
    {
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_FULL;
        GetThreadContext(thread, &ctx);
        if ((uintptr_t)ctx.Eip == (uintptr_t)epaddr)
            break;
        Sleep(10);
    }
    SuspendThread(thread);
    if (tmp == 100)
        return -1;

    /* Remotely parse the target process's module list to get the addresses
     * of the functions we need. This can only be done because we advanced
     * the target's execution to the entry point. */
    rep32(code, loaderaddr + loaderlen + jumperlen);
    rep32(code, (void *)get_proc_address(process, pid, "LoadLibraryA"));
    rep32(code, (void *)(uintptr_t)jumperlen);
    rep32(code, loaderaddr + loaderlen);
    rep32(code, epaddr);
    rep32(code, (void *)get_proc_address(process, pid, "GetCurrentProcess"));
    rep32(code, (void *)get_proc_address(process, pid, "WriteProcessMemory"));
    rep32(code, epaddr);

    /* Write our shellcodes into the target process */
    WriteProcessMemory(process, epaddr, code + loaderlen + jumperlen + liblen,
                       jumperlen, &tmp);
    if(tmp != jumperlen)
        return -1;
    FlushInstructionCache(process, epaddr, waiterlen);

    WriteProcessMemory(process, loaderaddr, code,
                       loaderlen + jumperlen + liblen, &tmp);
    if(tmp != loaderlen + jumperlen + liblen)
        return -1;

    return 0;
}

static intptr_t get_proc_address(void *process, DWORD pid, const char *func)
{
    char buf[1024];
    size_t buflen = strlen(func) + 1;

    MODULEENTRY32 entry;
    intptr_t ret = 0;
    DWORD tmp;
    void *list;
    int i, k;

    list = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    entry.dwSize = sizeof(entry);
    for(k = Module32First(list, &entry); k; k = Module32Next(list, &entry))
    {
        IMAGE_DOS_HEADER dos;
        IMAGE_NT_HEADERS nt;
        IMAGE_EXPORT_DIRECTORY expdir;

        uint32_t exportaddr;
        uint8_t const *base = entry.modBaseAddr;

        if (strcmp("kernel32.dll", entry.szModule))
            continue;

        ReadProcessMemory(process, base, &dos, sizeof(dos), &tmp);
        ReadProcessMemory(process, base + dos.e_lfanew, &nt, sizeof(nt), &tmp);

        exportaddr = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (!exportaddr)
            continue;

        ReadProcessMemory(process, base + exportaddr, &expdir, sizeof(expdir), &tmp);

        for (i = 0; i < (int)expdir.NumberOfNames; i++)
        {
            uint32_t nameaddr, funcaddr;
            uint16_t j;

            /* Look for our function name in the list of names */
            ReadProcessMemory(process, base + expdir.AddressOfNames
                                            + i * sizeof(DWORD),
                              &nameaddr, sizeof(nameaddr), &tmp);
            ReadProcessMemory(process, base + nameaddr, buf, buflen, &tmp);

            if (strcmp(buf, func))
                continue;

            /* If we found a function with this name, return its address */
            ReadProcessMemory(process, base + expdir.AddressOfNameOrdinals
                                            + i * sizeof(WORD),
                                &j, sizeof(j), &tmp);
            ReadProcessMemory(process, base + expdir.AddressOfFunctions
                                            + j * sizeof(DWORD),
                                &funcaddr, sizeof(funcaddr), &tmp);

            ret = (intptr_t)base + funcaddr;
            goto _finished;
        }
    }

_finished:
    CloseHandle(list);
    return ret;
}

#endif
