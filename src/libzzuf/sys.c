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

#if defined HAVE_STDINT_H
#   include <stdint.h>
#elif defined HAVE_INTTYPES_H
#   include <inttypes.h>
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

#if defined HAVE_WINDOWS_H
static void insert_funcs(void *);

/* TODO: get rid of this later */
HINSTANCE (WINAPI *LoadLibraryA_orig)(LPCSTR);
HINSTANCE WINAPI LoadLibraryA_new(LPCSTR path)
{
    void *ret;
    fprintf(stderr, "This is the diverted LoadLibraryA\n");
    ret = LoadLibraryA_orig(path);
    fprintf(stderr, "Now the real LoadLibraryA was called\n");
    return ret;
}

BOOL (WINAPI *AllocConsole_orig)(void);
BOOL WINAPI AllocConsole_new(void)
{
    fprintf(stderr, "Allocating console\n");
    return AllocConsole_orig();
}

BOOL (WINAPI *AttachConsole_orig)(DWORD);
BOOL WINAPI AttachConsole_new(DWORD d)
{
    fprintf(stderr, "Attaching console\n");
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

    VirtualQuery(_zz_sys_init, &mbi, sizeof(mbi));
    list = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    entry.dwSize = sizeof(entry);
    for(k = Module32First(list, &entry); k; k = Module32Next(list, &entry))
    {
        if(entry.hModule == mbi.AllocationBase)
            continue; /* Don't replace our own functions */

        insert_funcs(entry.hModule);
    }
    CloseHandle(list);
#else
    /* Nothing to do on our platform */
#endif
}

#if defined HAVE_WINDOWS_H
static void insert_funcs(void *module)
{
    struct { char const *lib, *name; void **old; void *new; }
    diversions[] =
    {
#define DIVERT(x) { "kernel32.dll", #x, &x##_orig, x##_new }
        DIVERT(LoadLibraryA),
        DIVERT(AllocConsole),
        DIVERT(AttachConsole),
    };

    unsigned long dummy;
    import_t import;
    thunk_t thunk;
    int k, j, i;

    import = (import_t)
        ImageDirectoryEntryToData(module, TRUE,
                                  IMAGE_DIRECTORY_ENTRY_IMPORT, &dummy);
    if(!import)
        return;

    for (k = 0; k < sizeof(diversions) / sizeof(*diversions); k++)
    {
        void *lib = GetModuleHandleA(diversions[k].lib);
        *diversions[k].old = (void *)GetProcAddress(lib, diversions[k].name);

        for(j = 0; import[j].Name; j++)
        {
            char *name = (char *)module + import[j].Name;
            if(lstrcmpiA(name, diversions[k].lib) != 0)
                continue;

            thunk = (thunk_t)((char *)module + import->FirstThunk);
            for(i = 0; thunk[i].u1.Function; i++)
            {
                void **func = (void **)&thunk[i].u1.Function;
                if(*func != *diversions[k].old)
                    continue;

                /* FIXME: The StarCraft 2 hack uses two methods for function
                 * diversion. See HookSsdt() and HookHotPatch(). */
                VirtualProtect(func, sizeof(func), PAGE_EXECUTE_READWRITE, &dummy);
                WriteProcessMemory(GetCurrentProcess(), func, &diversions[k].new,
                                   sizeof(diversions[k].new), NULL);
            }
        }
    }
}
#endif

