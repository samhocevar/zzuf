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
static void insert_func(void *, void *, void *);

/* TODO: get rid of this later */
HINSTANCE (__stdcall *LoadLibraryA_orig)(LPCSTR);
HINSTANCE __stdcall LoadLibraryA_new(LPCSTR path)
{
    void *ret;
    fprintf(stderr, "If you see this message, DLL preloading worked\n");
    ret = LoadLibraryA_orig(path);
    fprintf(stderr, "If you see this message, function diversion worked\n");
    return ret;
}
#endif

void _zz_sys_init(void)
{
#if defined HAVE_WINDOWS_H
    MEMORY_BASIC_INFORMATION mbi;
    MODULEENTRY32 entry;
    void *list, *kernel32;
    int k;

    kernel32 = GetModuleHandleA("kernel32.dll");
    LoadLibraryA_orig = (void *)GetProcAddress(kernel32, "LoadLibraryA");

    VirtualQuery(_zz_sys_init, &mbi, sizeof(mbi));
    list = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    entry.dwSize = sizeof(entry);
    for(k = Module32First(list, &entry); k; k = Module32Next(list, &entry))
    {
        if(entry.hModule == mbi.AllocationBase)
            continue; /* Don't replace our own functions */

        insert_func(entry.hModule, LoadLibraryA_orig, LoadLibraryA_new);
    }
    CloseHandle(list);
#else
    /* Nothing to do on our platform */
#endif
}

#if defined HAVE_WINDOWS_H
static void insert_func(void *module, void *old, void *new)
{
    unsigned long dummy;
    import_t import;
    thunk_t thunk;
    int j, i;

    import = (import_t)
        ImageDirectoryEntryToData(module, TRUE,
                                  IMAGE_DIRECTORY_ENTRY_IMPORT, &dummy);
    if(!import)
        return;

    for(j = 0; import[j].Name; j++)
    {
        char *name = (char *)module + import[j].Name;
        if(lstrcmpiA(name, "kernel32.dll") != 0)
            continue;

        thunk = (thunk_t)((char *)module + import->FirstThunk);
        for(i = 0; thunk[i].u1.Function; i++)
        {
            void **func = (void **)&thunk[i].u1.Function;
            if(*func != old)
                continue;

            VirtualProtect(func, sizeof(func), PAGE_EXECUTE_READWRITE, &dummy);
            WriteProcessMemory(GetCurrentProcess(), func, &new,
                               sizeof(new), NULL);
            return;
        }
    }
}
#endif

