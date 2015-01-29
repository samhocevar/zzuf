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
 *  myfork.c: launcher
 */

#include "config.h"

#define _INCLUDE_POSIX_SOURCE /* for STDERR_FILENO on HP-UX */
#define _BSD_SOURCE /* for setenv on glibc systems */

#if defined HAVE_STDINT_H
#   include <stdint.h>
#elif defined HAVE_INTTYPES_H
#   include <inttypes.h>
#endif
#include <stdio.h>
#include <stdlib.h> /* for setenv */
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

static int mypipe(int pipefd[2]);
static int run_process(zzuf_child_t *child, zzuf_opts_t *, int[][2]);

#if defined HAVE_WINDOWS_H
static int dll_inject(PROCESS_INFORMATION *, char const *);
static void *get_proc_address(void *, DWORD, char const *);
#endif

/*
 * Run a process, either by forking (Unix) or using the Windows API. The
 * child PID is stored in the child structure, and a communication channel
 * is set up using pipes.
 */
int myfork(zzuf_child_t *child, zzuf_opts_t *opts)
{
    /* Prepare communication pipes */
    int pipefds[3][2];
    for (int i = 0; i < 3; ++i)
    {
        if (mypipe(pipefds[i]) < 0)
        {
            perror("pipe");
            return -1;
        }
    }

    pid_t pid = run_process(child, opts, pipefds);
    if (pid < 0)
    {
        /* FIXME: close pipes */
        fprintf(stderr, "error launching `%s'\n", child->newargv[0]);
        return -1;
    }

    child->pid = pid;
    for (int i = 0; i < 3; ++i)
    {
        close(pipefds[i][1]);
        child->fd[i] = pipefds[i][0];
    }

    return 0;
}

/*
 * Create a pipe, a unidirectional channel for interprocess communication.
 */
static int mypipe(int pipefd[2])
{
#if defined HAVE_PIPE
    /* Unix, Linux, and nice systems: just use pipe() */
    return pipe(pipefd);

#elif defined HAVE__PIPE && !defined _WIN32
    /* Systems with _pipe() but not pipe(). They probably don't even
     * exist, apart from Win32 which we handle a different way.
     * The pipe is created with NOINHERIT otherwise both parts are
     * inherited. We then duplicate the part we want. */
    int ret = _pipe(pipefd, 512, _O_BINARY | O_NOINHERIT);
    int tmp = _dup(pipefd[1]);
    close(pipefd[1]);
    pipefd[1] = tmp;
    return ret;

#elif defined _WIN32
    /* Windows: create a unique name for the pipe and use the Win32 API
     * to create it. Inspired by
     * http://www.daniweb.com/software-development/cpp/threads/295780/using-named-pipes-with-asynchronous-io-redirection-to-winapi */
    static int pipe_cnt = 0;
    char pipe_name[BUFSIZ];
    _snprintf(pipe_name, sizeof(pipe_name), "\\\\.\\Pipe\\zzuf.%08x.%d",
              GetCurrentProcessId(), pipe_cnt++);

    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    /* At this time, the HANDLE is inheritable and can both read/write */
    HANDLE rpipe = CreateNamedPipeA(pipe_name,
                           PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
                           PIPE_TYPE_BYTE | PIPE_WAIT,
                           1, BUFSIZ, BUFSIZ, 0, &sa);

    /* Create a new handle for write access only; it must be inheritable */
    HANDLE wpipe = CreateFileA(pipe_name, GENERIC_WRITE, 0, &sa,
                               OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                               NULL);

    if (rpipe == INVALID_HANDLE_VALUE || wpipe == INVALID_HANDLE_VALUE)
        return -1;

    /* Create a new handle for the listener; not inheritable */
    HANDLE new_rpipe;
    if (!DuplicateHandle(GetCurrentProcess(), rpipe,
                         GetCurrentProcess(), &new_rpipe,
                         0, FALSE, DUPLICATE_SAME_ACCESS))
        return -1;

    /* Finally we can safetly close the pipe handle */
    CloseHandle(rpipe);

    /* Now we convert handle to fd */
    pipefd[0] = _open_osfhandle((intptr_t)new_rpipe, 0x0);
    pipefd[1] = _open_osfhandle((intptr_t)wpipe, 0x0);

    return 0;
#endif
}

#if !HAVE_SETENV
/*
 * Implement setenv() if not available on the system. We just call
 * putenv() on heap-allocated memory.
 * XXX: the memory allocated here is never freed by zzuf.
 */
static void setenv(char const *name, char const *value, int overwrite)
{
    if (!overwrite && getenv(name))
        return;

    char *str = malloc(strlen(name) + 1 + strlen(value) + 1);
    sprintf(str, "%s=%s", name, value);
    putenv(str);
}
#endif

static int run_process(zzuf_child_t *child, zzuf_opts_t *opts, int pipes[][2])
{
#if defined HAVE_FORK
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

    /* Fork and launch child */
    int pid = fork();
    if (pid < 0)
    {
        perror("fork");
        return -1;
    }

    if (pid != 0)
    {
        /* We are the parent. Close the pipe fds used for writing, since
         * we will only be reading. */
        for (int j = 3; j--; )
            close(pipes[j][1]);

        return pid;
    }

    /* We are the child. Close the pipe fds used for reading, since we
     * will only be writing. Also, if the fd number does not match what
     * we expect (for whatever reason), call dup2() and close the fd with
     * the wrong number. We loop in reverse order so that files[0] (the
     * debug fd) is done last, because it is the most important to us. */
    static int const fds[] = { DEBUG_FILENO, STDERR_FILENO, STDOUT_FILENO };
    for (int j = 3; j--; )
    {
        close(pipes[j][0]);
        if (pipes[j][1] != fds[j])
        {
            dup2(pipes[j][1], fds[j]);
            close(pipes[j][1]);
            pipes[j][1] = fds[j];
        }
    }
#endif

#if defined HAVE_SETRLIMIT && defined ZZUF_RLIMIT_MEM
    if (opts->maxmem >= 0)
    {
        struct rlimit rlim;
        rlim.rlim_cur = opts->maxmem * 1048576;
        rlim.rlim_max = opts->maxmem * 1048576;
        setrlimit(ZZUF_RLIMIT_MEM, &rlim);
    }
#endif

#if defined HAVE_SETRLIMIT && defined ZZUF_RLIMIT_CPU
    if (opts->maxcpu >= 0)
    {
        struct rlimit rlim;
        rlim.rlim_cur = opts->maxcpu;
        rlim.rlim_max = opts->maxcpu + 5;
        setrlimit(ZZUF_RLIMIT_CPU, &rlim);
    }
#endif

    /* Set environment variables */
    char buf[64];
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
    int len = strlen(opts->oldargv[0]);
    char *libpath =
               malloc(len + strlen(LIBDIR "/" LT_OBJDIR SONAME EXTRAINFO) + 1);
    strcpy(libpath, opts->oldargv[0]);

    /* If the binary name contains a '/', we look for a libzzuf in the
     * same directory. Otherwise, we only look into the system directory
     * to avoid shared library attacks. Write the result in libpath. */
    char *tmp = strrchr(libpath, '/');
    if (tmp)
    {
        strcpy(tmp + 1, LT_OBJDIR SONAME);
        if (access(libpath, R_OK) < 0)
            strcpy(libpath, LIBDIR "/" SONAME);
    }
    else
        strcpy(libpath, LIBDIR "/" SONAME);

    /* OSF1 only */
    strcat(libpath, EXTRAINFO);

    /* Do not clobber previous LD_PRELOAD values */
    tmp = getenv(PRELOAD);
    if (tmp && *tmp)
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

    if (execvp(child->newargv[0], child->newargv))
    {
        perror(child->newargv[0]);
        exit(EXIT_FAILURE);
    }

    exit(EXIT_SUCCESS);
    /* no return */
    return 0;

#elif HAVE_WINDOWS_H
    /* Inherit standard handles */
    STARTUPINFO sinfo;
    memset(&sinfo, 0, sizeof(sinfo));
    sinfo.cb = sizeof(sinfo);
    sinfo.hStdInput = INVALID_HANDLE_VALUE;
    sinfo.hStdOutput = (HANDLE)_get_osfhandle(pipes[2][1]);
    sinfo.hStdError = (HANDLE)_get_osfhandle(pipes[1][1]);
    sinfo.dwFlags = STARTF_USESTDHANDLES;

    /* Build the commandline */
    int len = 0;
    for (int i = 0; child->newargv[i]; ++i)
        len += (int)strlen(child->newargv[i]) + 1;
    char *cmdline = malloc(len);

    len = 0;
    for (int i = 0; child->newargv[i]; ++i)
    {
        strcpy(cmdline + len, child->newargv[i]);
        len += (int)strlen(child->newargv[i]) + 1;
        cmdline[len - 1] = ' ';
    }
    cmdline[len - 1] = '\0';

    /* Create the process in suspended state */
    PROCESS_INFORMATION pinfo;
    int ret = CreateProcess(child->newargv[0], cmdline, NULL, NULL, TRUE,
                            CREATE_SUSPENDED, NULL, NULL, &sinfo, &pinfo);
    free(cmdline);

    child->process_handle = pinfo.hProcess;
    child->pid            = pinfo.dwProcessId;

    if (!ret)
    {
        LPTSTR tmp;
        DWORD err = GetLastError();
        FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                      FORMAT_MESSAGE_FROM_SYSTEM     |
                      FORMAT_MESSAGE_IGNORE_INSERTS,
                      NULL, err, 0, (LPTSTR)&tmp, 0, NULL);
        fprintf(stderr, "error launching `%s': %s\n", child->newargv[0], tmp);
        LocalFree(tmp);
        return -1;
    }

    /* Insert the replacement code */
    ret = dll_inject(&pinfo, SONAME);
    if (ret < 0)
    {
        TerminateProcess(pinfo.hProcess, -1);
        return -1;
    }

    /* Insert your breakpoint here to have a chance to attach a debugger
     * to libzzuf.dll */
    ret = ResumeThread(pinfo.hThread);
    if (ret == -1)
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

    /* This payload allows us to load arbitrary module located
     * at the end of this buffer */
    static uint8_t const loader[] =
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
#   define loader               loader32
#   define LoadLibraryAOffset   0x04

    /* This payload allows us to load arbitrary module located
     * at the end of this buffer */
    static uint8_t const loader[] =
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

    /* We use this code to make the targeted process wait for us */
    static uint8_t const wait[] = "\xeb\xfe"; /* jmp $-1 */
    size_t wait_len = sizeof(wait) - 1;

    void *process = pinfo->hProcess;
    void *thread = pinfo->hThread;
    SIZE_T written = 0;
    BOOL tmp;

    /* Payload */
    size_t payload_len = sizeof(loader) - 1 + strlen(lib) + 1;
    uint8_t *payload = malloc(payload_len);
    if (payload == NULL)
        goto error;

    /* Use the main thread to inject our library */
    CONTEXT ctxt;
    ctxt.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(thread, &ctxt))
        goto error;

    /* Make the target program wait when it reaches the original entry
     * point, because we can't do many thing from the Windows loader */

    DWORD_PTR oep = ctxt.LoaderRegister; /* Original Entry Point */
    uint8_t orig_data[2];
    tmp = ReadProcessMemory(process, (LPVOID)oep, orig_data,
                            sizeof(orig_data), &written);
    if (!tmp || written != sizeof(orig_data))
        goto error; /* save original opcode */

    tmp = WriteProcessMemory(process, (LPVOID)oep, wait, wait_len, &written);
    if (!tmp || written != wait_len)
        goto error; /* write jmp short $-1 */
    if (!FlushInstructionCache(process, (LPVOID)oep, wait_len))
        goto error;
    if (ResumeThread(thread) == (DWORD)-1)
        goto error;

    /* Stop when the program reachse the oep */
    while (oep != ctxt.InstructionPointer)
    {
        if (!GetThreadContext(thread, &ctxt))
            goto error;
        Sleep(10);
    }

    if (SuspendThread(thread) == (DWORD)-1)
        goto error;

    /* Resolve LoadLibraryA from the target process memory context */
    DWORD pid = pinfo->dwProcessId;
    void *rldlib = get_proc_address(process, pid, "LoadLibraryA");
    if (rldlib == NULL)
        goto error;

    void *rpl = VirtualAllocEx(process, NULL, payload_len,
                               MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (rpl == NULL)
        goto error;

    /* Emulate a call to the loader code, thus the ret instruction from
     * loader will get (e|r)ip back to the original entry point */
    ctxt.StackPointer -= sizeof(oep);
    tmp = WriteProcessMemory(process, (LPVOID)ctxt.StackPointer,
                             &oep, sizeof(oep), &written);
    if (!tmp || written != sizeof(oep))
        goto error;
    ctxt.InstructionPointer = (DWORD_PTR)rpl;
    if (!SetThreadContext(thread, &ctxt))
        goto error;

    /* Forge the payload */
    memcpy(payload, loader, sizeof(loader) - 1);
    /* Write the address of LoadLibraryA */
    memcpy(payload + LoadLibraryAOffset, &rldlib, sizeof(rldlib));
    /* Write the first parameter of LoadLibraryA */
    strcpy((char *)(payload + sizeof(loader) - 1), lib);

    tmp = WriteProcessMemory(process, rpl, payload, payload_len, &written);
    if (!tmp || written != payload_len)
        goto error;

    /* Restore original opcode */
    tmp = WriteProcessMemory(process, (LPVOID)oep, orig_data,
                             sizeof(orig_data), &written);
    if (!tmp || written != sizeof(orig_data))
        goto error;

    if (!FlushInstructionCache(process, rpl, payload_len))
        goto error;
    if (!FlushInstructionCache(process, (LPVOID)oep, sizeof(orig_data)))
        goto error;

    /* We must not free remote allocated memory since they will be used
     * after the process will be resumed */
    free(payload);
    return 0;

error:
    free(payload);
    return -1;
}

#undef InstructionPointer
#undef StackPointer
#undef LoaderRegister
#undef LoadLibraryAOffset

static void *get_proc_address(void *process, DWORD pid, const char *func)
{
    void *ret = 0;

    MODULEENTRY32 entry;
    entry.dwSize = sizeof(entry);
    void *list = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);

    for (int k = Module32First(list, &entry); k; k = Module32Next(list, &entry))
    {
        IMAGE_DOS_HEADER dos;
        IMAGE_NT_HEADERS nt;
        IMAGE_EXPORT_DIRECTORY expdir;

        uint32_t exportaddr;
        uint8_t *base = entry.modBaseAddr;

        if (stricmp("kernel32.dll", entry.szModule))
            continue;

        SIZE_T tmp;
        ReadProcessMemory(process, base, &dos, sizeof(dos), &tmp);
        ReadProcessMemory(process, base + dos.e_lfanew, &nt, sizeof(nt), &tmp);

        exportaddr = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (!exportaddr)
            continue;

        ReadProcessMemory(process, base + exportaddr, &expdir, sizeof(expdir), &tmp);

        for (int i = 0; i < (int)expdir.NumberOfNames; ++i)
        {
            uint32_t nameaddr;
            /* Look for our function name in the list of names */
            ReadProcessMemory(process, base + expdir.AddressOfNames
                                            + i * sizeof(DWORD),
                              &nameaddr, sizeof(nameaddr), &tmp);
            char buf[1024];
            size_t buflen = strlen(func) + 1;
            ReadProcessMemory(process, base + nameaddr, buf, buflen, &tmp);

            if (strcmp(buf, func))
                continue;

            /* If we found a function with this name, return its address */
            uint16_t j;
            ReadProcessMemory(process, base + expdir.AddressOfNameOrdinals
                                            + i * sizeof(WORD),
                              &j, sizeof(j), &tmp);

            uint32_t funcaddr;
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
