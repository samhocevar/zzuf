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
static void insert_funcs(void);

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

    insert_funcs();

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

#define MK_JMP_JD(dst, src) ((dst) - ((src) + 5))

/* zz_lde is a _very_ simple length disassemble engine.
 * x64 is not tested and should not work. */
static int zz_lde(uint8_t *code, int required_size)
{
    int insn_size = 0;
    static uint8_t modrm_size[] = { 0, 1, 4, 0 }; /* [reg ...], [reg ... + sbyte], [reg ... + sdword], reg */

    while (insn_size < required_size)
    {
        uint8_t opcd = code[insn_size++];

        /* Simple instructions should be placed here */
        switch (opcd)
        {
        case 0x68: insn_size += 4; continue; /* PUSH Iv */
        case 0x6a: insn_size += 1; continue; /* PUSH Ib */
        default: break;
        }

        /* PUSH/POP rv */
        if ((opcd & 0xf0) == 0x50) continue;

        /* MOV Ev, Gv or Gv, Ev */
        else if (opcd == 0x89 || opcd == 0x8b)
        {
            uint8_t modrm = code[insn_size++];

            /* Does the instruciton have a SIB byte ? */
            if (((modrm & 0x7) == 0x4) && ((modrm >> 6) != 0x3))
                insn_size++;

            insn_size += modrm_size[modrm >> 6];

            continue;
        }


        /* If we can't disassemble the current instruction, we give up */
        return -1;
    }

    return insn_size;
}

/* This function allows to hook any API. To do so, it disassembles the beginning of the
 * targeted function and looks for, at least, 5 bytes (size of JMP Jd).
 * Then it writes a JMP Jv instruction to make the new_api executed.
 * Finally, trampoline_api contains a wrapper to call in order to execute the original API */
static int hook_inline(uint8_t *old_api, uint8_t *new_api, uint8_t **trampoline_api)
{
    int res             = -1;
    int patch_size      = 0;
    uint8_t *jmp_prolog = NULL;
    uint8_t *trampoline = NULL;
    DWORD old_prot;

    /* if we can't get enough byte, we quit */
    if ((patch_size = zz_lde(old_api, 5)) == -1)
        return -1;

    if ((jmp_prolog = malloc(patch_size)) == NULL) goto _out;
    memset(jmp_prolog, '\xcc', patch_size); /* We use 0xcc because the code after the jmp should be executed */

    *trampoline_api = NULL;

    jmp_prolog[0] = '\xe9'; /* jmp Jd */
    *(uint32_t *)(&jmp_prolog[1]) = MK_JMP_JD(new_api, old_api);

    trampoline = malloc(patch_size + 5); /* size of old byte + sizeof of jmp Jd */
    memcpy(trampoline, old_api, patch_size);
    *(uint8_t  *)&trampoline[patch_size]     = '\xe9'; /* jmp Jd */
    *(uint32_t *)&trampoline[patch_size + 1] = MK_JMP_JD(old_api + patch_size, trampoline + patch_size);

    /* We must make the trampoline executable, this line is required because of DEP */
    /* NOTE: We _must_ set the write protection, otherwise the heap allocator will crash ! */
    if (!VirtualProtect(trampoline, patch_size + 5, PAGE_EXECUTE_READWRITE, &old_prot)) goto _out;

    /* We patch the targeted API, so we must set it as writable */
    if (!VirtualProtect(old_api, patch_size, PAGE_EXECUTE_READWRITE, &old_prot)) goto _out;
    memcpy(old_api, jmp_prolog, patch_size);
    VirtualProtect(old_api, patch_size, old_prot, &old_prot); /* we don't care if this functon fails */

    *trampoline_api = trampoline;

    res = 0;

_out:
    if (res < 0)
    {
        if (*trampoline_api)
        {
            free(*trampoline_api);
            trampoline_api = NULL;
        }
    }

    if (jmp_prolog != NULL) free(jmp_prolog);

    return res;
}

static void insert_funcs(void)
{
    static zzuf_table_t *list[] =
    {
        table_win32,
    };

    zzuf_table_t *diversion;
    HMODULE lib;

    for (diversion = *list; diversion->lib; diversion++)
    {
        uint8_t *old_api;
        uint8_t *trampoline_api;

        /* most of the time, the dll is already loaded */
        if ((lib = GetModuleHandleA(diversion->lib)) == NULL)
        {
           if ((lib = LoadLibraryA(diversion->lib)) == NULL)
           {
               fprintf(stderr, "unable to load %s\n", diversion->lib);
               return;
           }
        }
        if ((old_api = (uint8_t *)GetProcAddress(lib, diversion->name)) == NULL)
        {
            fprintf(stderr, "unable to get pointer to %s\n", diversion->name);
            return;
        }
        if (hook_inline(old_api, diversion->new, &trampoline_api) < 0)
        {
            fprintf(stderr, "hook_inline failed while hooking %s!%s\n", diversion->lib, diversion->name);
            return;
        }
        *diversion->old = trampoline_api;
    }
}

#endif
