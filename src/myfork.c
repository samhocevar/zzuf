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
static void rep32(uint8_t *buf, void *addr);
static int dll_inject(PROCESS_INFORMATION *, char const *);
static void *get_proc_address(void *, DWORD, char const *);
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
#elif defined HAVE__PIPE && !defined _WIN32
        int tmp;
        /* The pipe is created with NOINHERIT otherwise both parts are
         * inherited. We then duplicate the part we want. */
        ret = _pipe(pipes[i], 512, _O_BINARY | O_NOINHERIT);
        tmp = _dup(pipes[i][1]);
        close(pipes[i][1]);
        pipes[i][1] = tmp;
#elif defined _WIN32
        // http://www.daniweb.com/software-development/cpp/threads/295780/using-named-pipes-with-asynchronous-io-redirection-to-winapi
        {
            static int pipe_cnt = 0;
            char pipe_name[BUFSIZ];
            HANDLE pipe_hdl[2];         /* [0] read | [1] write */
            HANDLE new_hdl;
            SECURITY_ATTRIBUTES sa;
            sa.nLength              = sizeof(sa);
            sa.bInheritHandle       = TRUE;
            sa.lpSecurityDescriptor = NULL;

            ret = 0;

            /* Since we have to use a named pipe, we have to make sure the name is unique */
            _snprintf(pipe_name, sizeof(pipe_name), "\\\\.\\Pipe\\zzuf.%08x.%d", GetCurrentProcessId(), pipe_cnt++);

            /* At this time, the HANDLE is inheritable and can both read/write */
            if ((pipe_hdl[0] = CreateNamedPipeA(
                pipe_name,
                PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_WAIT,
                1,
                BUFSIZ,
                BUFSIZ,
                0,
                &sa)) == INVALID_HANDLE_VALUE ||

            /* Create a new handle for writing access only and it must be inheritable */
            (pipe_hdl[1] = CreateFileA(
                pipe_name,
                GENERIC_WRITE,
                0,
                &sa,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                NULL)) == INVALID_HANDLE_VALUE)
                ret = -1;

            /* Now we create a new handle for the listener which is not inheritable */
            if (!DuplicateHandle(
                GetCurrentProcess(), pipe_hdl[0],
                GetCurrentProcess(), &new_hdl,
                0, FALSE,
                DUPLICATE_SAME_ACCESS))
                ret = -1;

            /* Finally we can safetly close the pipe handle */
            CloseHandle(pipe_hdl[0]);

            /* Now we convert handle to fd */
            pipes[i][0] = _open_osfhandle((intptr_t)new_hdl,     0x0);
            pipes[i][1] = _open_osfhandle((intptr_t)pipe_hdl[1], 0x0);
        }
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
    /* Only enforce flat namespace in preload mode */
    if (opts->opmode == OPMODE_PRELOAD)
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
#if defined _WIN32
    sprintf(buf, "%i", _get_osfhandle(pipes[0][1]));
#else
    sprintf(buf, "%i", pipes[0][1]);
#endif
    setenv("ZZUF_DEBUGFD", buf, 1);
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
    sinfo.hStdInput = INVALID_HANDLE_VALUE;
    sinfo.hStdOutput = (HANDLE)_get_osfhandle(pipes[2][1]);
    sinfo.hStdError = (HANDLE)_get_osfhandle(pipes[1][1]);
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

    child->process_handle = pinfo.hProcess;
    child->pid            = pinfo.dwProcessId;

    if (!ret)
    {
        LPTSTR buf;
        DWORD err = GetLastError();
        FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                      FORMAT_MESSAGE_FROM_SYSTEM     |
                      FORMAT_MESSAGE_IGNORE_INSERTS,
                      NULL, err, 0, (LPTSTR)&buf, 0, NULL);
        fprintf(stderr, "error launching `%s': %s\n", child->newargv[0], buf);
        LocalFree(buf);
        return -1;
    }

    /* Insert the replacement code */
    ret = dll_inject(&pinfo, SONAME);
    if(ret < 0)
    {
        TerminateProcess(pinfo.hProcess, -1);
        return -1;
    }

    /* insert your breakpoint here to have a chance to attach a debugger to libzzuf.dll */
    ret = ResumeThread(pinfo.hThread);
    if(ret == -1)
    {
        TerminateProcess(pinfo.hProcess, -1);
        return -1;
    }

    return (long int)pinfo.hProcess;
#endif
}

#if defined HAVE_WINDOWS_H

static int dll_inject(PROCESS_INFORMATION *pinfo, char const *lib)
{
#ifdef  _M_AMD64
#   define InstructionPointer   Rip
#   define StackPointer         Rsp
#   define LoaderRegister       Rcx
#   define LoadLibraryAOffset   0x15

    /* This payload allows us to load arbitrary module located at the end of this buffer */
    static uint8_t const ldr[] =
    {
        "\x55"                          /* push rbp              */
        "\x48\x89\xE5"                  /* mov rbp,rsp           */
        "\x48\x83\xEC\x20"              /* sub rsp,byte +0x20    */
        "\x48\x83\xE4\xF0"              /* and rsp,byte -0x10    */
        "\x48\x8D\x0D\x14\x00\x00\x00"  /* lea rcx,[rel 0x27]    */
        "\x48\xB8________"              /* mov rax, LoadLibraryA */
        "\xFF\xD0"                      /* call rax              */
        "\x48\x85\xC0"                  /* test rax,rax          */
        "\x75\x01"                      /* jnz 0x25              */
        "\xCC"                          /* int3                  */
        "\xC9"                          /* leave                 */
        "\xC3"                          /* ret                   */
    };

#elif defined (_M_IX86)
#   define InstructionPointer   Eip
#   define StackPointer         Esp
#   define LoaderRegister       Eax /* It seems the Windows loader store the oep as the first param
                                     * but by a side effect it's also contained in eax register */
#   define ldr                  ldr32
#   define LoadLibraryAOffset   0x04

    /* This payload allows us to load arbitrary module located at the end of this buffer */
    static uint8_t const ldr[] =
    {
        "\x60"                  /* pushad               */
        "\xEB\x0E"              /* jmp short 0x11       */
        "\xB8____"              /* mov eax,LoadLibraryA */
        "\xFF\xD0"              /* call eax             */
        "\x85\xC0"              /* test eax,eax         */
        "\x75\x01"              /* jnz 0xf              */
        "\xCC"                  /* int3                 */
        "\x61"                  /* popad                */
        "\xC3"                  /* ret                  */
        "\xE8\xED\xFF\xFF\xFF"  /* call dword 0x3       */
    };
#else
#   error Unimplemented architecture !
#endif

    int res = -1;

    /* We use this code to make the targeted process waits for us */
    static uint8_t const wait[] = "\xeb\xfe"; /* jmp $-1 */
    size_t wait_len             = sizeof(wait) - 1;
    uint8_t orig_data[2];

    void *process   = pinfo->hProcess;
    void *thread    = pinfo->hThread;
    DWORD pid       = pinfo->dwProcessId;
    void *rldlib    = NULL;
    SIZE_T written  = 0;
    DWORD old_prot  = 0;

    /* Payload */
    void *rpl       = NULL;
    uint8_t *pl     = NULL;
    size_t pl_len   = sizeof(ldr) - 1 + strlen(lib) + 1;

    CONTEXT ctxt;
    DWORD_PTR oep; /* Original Entry Point */

    /* Use the main thread to inject our library */
    ctxt.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(thread, &ctxt)) goto _return;

    /* Make the target program waits when it reachs the original entry point, because we can't do many thing from the windows loader */
    oep = ctxt.LoaderRegister;
    if (!ReadProcessMemory(process, (LPVOID)oep, orig_data, sizeof(orig_data), &written) || written != sizeof(orig_data)) goto _return; /* save original opcode */
    if (!WriteProcessMemory(process, (LPVOID)oep, wait, wait_len , &written) || written != wait_len) goto _return;                      /* write jmp short $-1 */
    if (!FlushInstructionCache(process, (LPVOID)oep, wait_len)) goto _return;
    if (ResumeThread(thread) == (DWORD)-1) goto _return;

    /* Stop when the program reachs the oep */
    while (oep != ctxt.InstructionPointer)
    {
        if (!GetThreadContext(thread, &ctxt)) goto _return;
        Sleep(10);
    }

    if (SuspendThread(thread) == (DWORD)-1) goto _return;

    /* Resolve LoadLibraryA from the target process memory context */
    if ((rldlib = get_proc_address(process, pid, "LoadLibraryA")) == NULL) goto _return;

    if ((rpl = VirtualAllocEx(process, NULL, pl_len, MEM_COMMIT, PAGE_EXECUTE_READWRITE)) == NULL) goto _return;

    /* Emulate a call to the ldr code, thus the ret instruction from ldr will get (e|r)ip back to the original entry point */
    ctxt.StackPointer -= sizeof(oep);
    if (!WriteProcessMemory(process, (LPVOID)ctxt.StackPointer, &oep, sizeof(oep), &written) || written != sizeof(oep)) goto _return;
    ctxt.InstructionPointer = (DWORD_PTR)rpl;
    if (!SetThreadContext(thread, &ctxt)) goto _return;

    /* Forge the payload */
    if ((pl = (uint8_t *)malloc(pl_len)) == NULL) goto _return;
    memcpy(pl, ldr, sizeof(ldr) - 1);
    memcpy(pl + LoadLibraryAOffset, &rldlib, sizeof(rldlib));        /* Write the address of LoadLibraryA         */
    strcpy((char *)(pl + sizeof(ldr) - 1), lib);                    /* Write the first parameter of LoadLibraryA */

    if (!WriteProcessMemory(process, rpl, pl, pl_len, &written) || written != pl_len) goto _return;

    /* Restore original opcode */
    if (!WriteProcessMemory(process, (LPVOID)oep, orig_data, sizeof(orig_data), &written) || written != sizeof(orig_data)) goto _return;

    if (!FlushInstructionCache(process, rpl, pl_len)) goto _return;
    if (!FlushInstructionCache(process, (LPVOID)oep, sizeof(orig_data))) goto _return;

    res = 0;
_return:
    if (pl != NULL) free(pl);

    /* We must not free remote allocated memory since they will be used after the process will be resumed */
    return res;

#undef InstructionPointer
#undef StackPointer
#undef LoaderRegister
#undef LoadLibraryAOffset
}

static void *get_proc_address(void *process, DWORD pid, const char *func)
{
    char buf[1024];
    size_t buflen = strlen(func) + 1;

    MODULEENTRY32 entry;
    void *ret = 0;
    SIZE_T tmp;
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
        uint8_t *base = entry.modBaseAddr;

        if (stricmp("kernel32.dll", entry.szModule))
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

            ret = base + funcaddr;
            goto _finished;
        }
    }

_finished:
    CloseHandle(list);
    return ret;
}

#endif
