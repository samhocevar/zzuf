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
 *  sys.c: system-dependent initialisation
 */

#include "config.h"

/* Need this for RTLD_NEXT */
#define _GNU_SOURCE

#if defined HAVE_STDINT_H
#   include <stdint.h>
#elif defined HAVE_INTTYPES_H
#   include <inttypes.h>
#endif

#ifdef HAVE_DLFCN_H
#   include <dlfcn.h>
#endif

#if defined HAVE_WINDOWS_H
#   include <windows.h>
#   include <imagehlp.h>
#   include <tlhelp32.h>
#   define import_t PIMAGE_IMPORT_DESCRIPTOR
#   define thunk_t PIMAGE_THUNK_DATA
#endif

#include <stdio.h>

#include "sys.h"
#include "lib-load.h"

#if defined HAVE_DLFCN_H
void *_zz_dl_lib = RTLD_NEXT;
#endif

#if defined HAVE_WINDOWS_H
static void insert_funcs(void *);

/* TODO: get rid of this later */
HINSTANCE (WINAPI *LoadLibraryA_orig)(LPCSTR);
HINSTANCE WINAPI LoadLibraryA_new(LPCSTR path)
{
    return LoadLibraryA_orig(path);
}

BOOL (WINAPI *AllocConsole_orig)(void);
BOOL WINAPI AllocConsole_new(void)
{
    return AllocConsole_orig();
}

BOOL (WINAPI *AttachConsole_orig)(DWORD);
BOOL WINAPI AttachConsole_new(DWORD d)
{
    return AttachConsole_orig(d);
}
#endif

void _zz_sys_init(void)
{
#if defined HAVE_WINDOWS_H
    MEMORY_BASIC_INFORMATION mbi;
    MODULEENTRY32 entry;
    void *list;
    int k;

    /* Enumerate all loaded objects and overwrite some functions */
    VirtualQuery(_zz_sys_init, &mbi, sizeof(mbi));
    list = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    entry.dwSize = sizeof(entry);
    for(k = Module32First(list, &entry); k; k = Module32Next(list, &entry))
    {
        if(entry.hModule == mbi.AllocationBase)
            continue; /* Don't replace our own functions */

        fprintf(stderr, "diverting functions from %s\n", entry.szModule);
        insert_funcs(entry.hModule);
    }
    CloseHandle(list);
#elif defined HAVE_DLFCN_H
    /* If glibc is recent enough, we use dladdr() to get its address. This
     * way we are sure that the symbols we load are the most recent version,
     * or we may get weird problems. We choose fileno as a random symbol to
     * get, because we know we don't divert it. */
#   if HAVE_DLADDR
    Dl_info di;
    if (dladdr(&fileno, &di) != 0)
    {
        void *lib = dlopen(di.dli_fname, RTLD_NOW);
        if (lib)
            _zz_dl_lib = lib;
    }
#   endif
#else
    /* Nothing to do on our platform */
#endif
}

#if defined HAVE_WINDOWS_H
static void insert_funcs(void *module)
{
    static zzuf_table_t *list[] =
    {
        table_win32,
    };

    zzuf_table_t *diversion;
    void *lib;
    unsigned long dummy;
    import_t import;
    thunk_t thunk;
    int k, j, i;

    import = (import_t)
        ImageDirectoryEntryToData(module, TRUE,
                                  IMAGE_DIRECTORY_ENTRY_IMPORT, &dummy);
    if(!import)
        return;

    for (k = 0, diversion = NULL; k < sizeof(list) / sizeof(*list); )
    {
        if (!diversion)
            diversion = list[k];

        if (!diversion->lib)
        {
            k++;
            diversion = NULL;
            continue;
        }

        fprintf(stderr, "diverting method %s (from %s)\n",
                        diversion->name, diversion->lib);

        lib = GetModuleHandleA(diversion->lib);
        *diversion->old = (void *)GetProcAddress(lib, diversion->name);

        for(j = 0; import[j].Name; j++)
        {
            char *name = (char *)module + import[j].Name;
            if(lstrcmpiA(name, diversion->lib) != 0)
                continue;

            thunk = (thunk_t)((char *)module + import[j].FirstThunk);
            for(i = 0; thunk[i].u1.Function; i++)
            {
                void **func = (void **)&thunk[i].u1.Function;
                if(*func != *diversion->old)
                    continue;

                /* FIXME: The StarCraft 2 hack uses two methods for function
                 * diversion. See HookSsdt() and HookHotPatch(). */
                VirtualProtect(func, sizeof(func), PAGE_EXECUTE_READWRITE, &dummy);
                WriteProcessMemory(GetCurrentProcess(), func, &diversion->new,
                                    sizeof(diversion->new), NULL);
            }
        }

        diversion++;
    }
}
#endif
