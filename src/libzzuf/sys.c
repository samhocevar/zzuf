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
#endif

#if HAVE_DLFCN_H && HAVE_DLADDR && !__APPLE__ && (__GNUC__ || __clang__)
extern void __asan_init_v3(void) __attribute__((weak));
#endif

void _zz_sys_init(void)
{
#if defined HAVE_WINDOWS_H

    insert_funcs();

#elif HAVE_DLFCN_H && !__APPLE__
    /* If glibc is recent enough, we use dladdr() to get its address. This
     * way we are sure that the symbols we load are the most recent version,
     * or we may get weird problems. We choose fileno as a random symbol to
     * get, because we know we don't divert it. */

#if HAVE_DLADDR && (__GNUC__ || __clang__)
    /* XXX: for some reason we conflict with libasan. We would like to avoid
     * RTLD_NEXT because it causes problems with versioned symbols. However,
     * if we do that, libasan enters infinite recursion. So we just disable
     * this workaround if libasan is detected.
     * If we don’t do this, here’s a program that crashes when fuzzed:
     *  echo 'int main() {}' | gcc -xc -g -ggdb -fsanitize=address -   */
    if (&__asan_init_v3 == NULL)
#   endif
    {
#   if HAVE_DLADDR
        Dl_info di;
        if (dladdr(&fprintf, &di) != 0)
        {
            void *lib = dlopen(di.dli_fname, RTLD_NOW);
            if (lib)
                _zz_dl_lib = lib;
        }
#   endif
    }
#else
    /* Nothing to do on our platform */
#endif
}

#if defined HAVE_WINDOWS_H

#define MK_JMP_JD(dst, src) ((dst) - ((src) + 5))

static int modrm_sib_size(uint8_t* code)
{
    static uint8_t modrm_size[] = { 0, 1, 4, 0 }; /* [reg ...], [reg ... + sbyte], [reg ... + sdword], reg */
    uint8_t modrm = *code;

    if (modrm == 0x05) /* [(rip) + sdword] */
        return 1 + 4;

    /* Does this instruction have a SIB byte ? */
    return 1 + (!!(((modrm & 0x7) == 0x4) && ((modrm >> 6) != 0x3))) + modrm_size[modrm >> 6];
}

/* zz_lde is a _very_ simple length disassemble engine. */
static int zz_lde(uint8_t *code)
{
    int insn_size = 0;

    uint8_t opcd = code[insn_size++];
    int imm_size = 4; /* Iv */

#ifdef _M_AMD64
    // REX prefix
    if ((opcd & 0xf8) == 0x48)
    {
        imm_size = 8; /* REX.W */
        opcd = code[insn_size++];
    }
#endif

    /* Simple instructions should be placed here */
    switch (opcd)
    {
    case 0x68:
        return (insn_size + 4); /* PUSH Iv */
    case 0x6a:
        return (insn_size + 1); /* PUSH Ib */
    case 0x90:
        return insn_size;       /* NOP     */
    case 0xb8:
    case 0xb9:
    case 0xba:
    case 0xbb:
    case 0xbc:
    case 0xbd:
    case 0xbe:
    case 0xbf:
        return insn_size + 5;   /* MOV immediate */
    default:
        break;
    }

    /* PUSH/POP rv */
    if ((opcd & 0xf0) == 0x50)
        return insn_size;

    /* MNEM E?, G? or G?, E? */
    switch (opcd)
    {
    case 0x89: /* mov Ev, Gv */
    case 0x8b: /* mov Gv, Ev */
        return (insn_size + modrm_sib_size(code + insn_size));

    case 0x80: /* Group#1 Eb, Ib */
    case 0x82: /* Group#1 Eb, Ib */
    case 0x83: /* Group#1 Ev, Ib */
        return (insn_size + (modrm_sib_size(code + insn_size) + 1));

    case 0x81: /* Group#1 Ev, Iz */
        return (insn_size + (modrm_sib_size(code + insn_size) + 4));

    case 0xff:
        if ((code[insn_size] & 0x38) == 0x30) /* PUSH Ev */
            return (insn_size + modrm_sib_size(code + insn_size));
        break;

    default:
        fprintf(stderr, "unknown opcode %02x\n", opcd);
        break;
    }

    return 0;
}

/* This function returns the required size to insert a patch */
static int compute_patch_size(uint8_t *code, int required_size)
{
    int patch_size = 0;
    while (patch_size < required_size)
    {
        int insn_size = zz_lde(code + patch_size);
        if (insn_size == 0)
            return -1;
        patch_size += insn_size;
    }
    return patch_size;
}

static void make_jmp32(uint8_t *src, uint8_t *dst, uint8_t *code)
{
    *(uint8_t  *)(code + 0) = 0xe9;             /* JMP Jd */
    *(uint32_t *)(code + 1) = (uint32_t)MK_JMP_JD(dst, src);
}

#ifdef _M_AMD64
static void make_jmp64(uint8_t *dst, uint8_t *code)
{
    memcpy(code, "\x48\xb8", 2);                /* MOV rAX, Iq */
    *(uintptr_t *)(code + 2) = (uintptr_t)dst;
    memcpy(code + 10, "\xff\xe0", 2);           /* JMP rAX */
}
#endif

/* This function allocates and fills a trampoline for the function pointed by code. It also tries to handle some relocations. */
static int make_trampoline(uint8_t *code, size_t patch_size, uint8_t **trampoline_buf, size_t *trampoline_size)
{
    uint8_t *trampoline;

    *trampoline_buf  = NULL;
    *trampoline_size = 0;

#ifdef _M_AMD64
    {
        size_t code_offset = 0;
        size_t trampoline_offset = 0;
        const size_t reloc_size  = -7 /* size of mov rax, [rip + ...] */ +10 /* size of mov rax, Iq */;

        trampoline = malloc(patch_size + reloc_size + 13); /* Worst case */
        if (trampoline == NULL)
            return -1;
        memset(trampoline, 0xcc, patch_size + 13);

        while (code_offset < patch_size)
        {
            int insn_size = zz_lde(code + code_offset);
            if (insn_size == 0)
                return -1;

            /* mov rax, [rip + ...] is the signature for stack cookie */
            if (!memcmp(code + code_offset, "\x48\x8b\x05", 3))
            {
                uint64_t *cookie_address = (uint64_t *)(code + code_offset + insn_size + *(uint32_t *)(code + code_offset + 3));
                patch_size              += reloc_size;

                memcpy(trampoline + trampoline_offset, "\x48\xb8", 2); /* MOV rAX, Iq */
                *(uint64_t *)(trampoline + trampoline_offset + 2) = *cookie_address;
                trampoline_offset += 10;
            }
            else
            {
                *trampoline_size += insn_size;
                memcpy(trampoline + trampoline_offset, code + code_offset, insn_size);
                trampoline_offset += insn_size;
            }

            code_offset += insn_size;
        }


        /* We can't use make_jmp64 since rAX is used by the __security_cookie */
        memcpy(trampoline + trampoline_offset, "\x49\xba", 2); /* MOV r10, Iq */
        *(uint64_t *)(trampoline + trampoline_offset + 2) = (uint64_t)(code + code_offset);
        memcpy(trampoline + trampoline_offset + 10, "\x41\xff\xe2", 3); /* JMP r10 */

        *trampoline_buf  = trampoline;
        *trampoline_size = trampoline_offset;
        return 0;
    }
#elif _M_IX86
    trampoline = malloc(patch_size + 5);
    if (trampoline == NULL)
        return -1;
    memcpy(trampoline, code, patch_size);
    make_jmp32(trampoline + patch_size, code + patch_size, trampoline + patch_size);

    *trampoline_size = patch_size;
    *trampoline_buf  = trampoline;
    return 0;
#else
#   error Unsupported architecture !
#endif
}

/*
 * Sometimes Windows APIs are a stub and contain only a JMP to the real function.
 * To avoid to relocate a JMP, we use the destination address.
 */
static int relocate_hook(uint8_t **code)
{
    uint8_t *cur_code = *code;

#ifdef _M_AMD64
    // we ignore the REX prefix
    if ((*cur_code & 0xf8) == 0x48)
        ++cur_code;
#endif

    /* JMP Jd */
    if (*cur_code == 0xe9)
    {
        *cur_code += (5 + *(uint32_t *)(cur_code + 1));
        return 0;
    }

    /* JMP [(rip)+addr] */
    else if (!memcmp(cur_code, "\xff\x25", 2))
    {
#ifdef _M_AMD64
        uint8_t **dst_addr = (uint8_t **)(cur_code + 6 + *(uint32_t *)(cur_code + 2));
        *code = *dst_addr;
#elif _M_IX86
        /* UNTESTED ! */
        uint8_t **dst_addr = (uint8_t **)(*(uint32_t *)(cur_code + 2));
        *code = *dst_addr;
#else
#   error Unsupported architecture !
#endif
        return 0;
    }

    return -1;
}

/* This function allows to hook any API. To do so, it disassembles the beginning of the
 * targeted function and looks for, at least, 5 bytes (size of JMP Jd).
 * Then it writes a JMP Jv instruction to make the new_api executed.
 * Finally, trampoline_api contains a wrapper to call in order to execute the original API */
static int hook_inline(uint8_t *old_api, uint8_t *new_api, uint8_t **trampoline_api)
{
    int res                 = -1;
    int required_size       = 5;
    int patch_size          = 0;
    uint8_t jmp_prolog[12];
    uint8_t *trampoline     = NULL;
    size_t trampoline_size  = 0;
    DWORD old_prot;
    uint8_t *reloc_old_api  = old_api;

    while ((relocate_hook(&reloc_old_api)) >= 0)
        old_api = reloc_old_api;

    *trampoline_api = NULL;

    memset(jmp_prolog, 0xcc, sizeof(jmp_prolog));

#ifdef _M_AMD64
    if (new_api - old_api > 0xffffffff)
    {
        required_size = 12;
        make_jmp64(new_api, jmp_prolog);
    }
    else make_jmp32(old_api, new_api, jmp_prolog);
#elif _M_IX86
    make_jmp32(old_api, new_api, jmp_prolog);
#else
#   error Unsupported architecture !
#endif

    /* if we can't get enough byte, we quit */
    if ((patch_size = compute_patch_size(old_api, required_size)) == -1)
    {
        fprintf(stderr, "cannot compute patch size\n");
        return -1;
    }

    if (make_trampoline(old_api, patch_size, &trampoline, &trampoline_size) < 0)
    {
        fprintf(stderr, "cannot make trampoline\n");
        goto _out;
    }

    /* We must make the trampoline executable, this line is required because of DEP */
    /* NOTE: We _must_ set the write protection, otherwise the heap allocator will crash ! */
    if (!VirtualProtect(trampoline, trampoline_size, PAGE_EXECUTE_READWRITE, &old_prot))
    {
        fprintf(stderr, "cannot make the trampoline writable\n");
        goto _out;
    }

    /* We patch the targeted API, so we must set it as writable */
    if (!VirtualProtect(old_api, patch_size, PAGE_EXECUTE_READWRITE, &old_prot))
    {
        fprintf(stderr, "cannot make old API writable\n");
        goto _out;
    }
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

    return res;
}

static void insert_funcs(void)
{
    static zzuf_table_t *list[] =
    {
        table_win32,
    };

    for (zzuf_table_t *diversion = *list; diversion->lib; ++diversion)
    {
        /* most of the time, the dll is already loaded */
        HMODULE lib = GetModuleHandleA(diversion->lib);
        if (lib == NULL)
        {
           lib = LoadLibraryA(diversion->lib);
           if (lib == NULL)
           {
               fprintf(stderr, "unable to load %s\n", diversion->lib);
               continue;
           }
        }

        uint8_t *old_api = (uint8_t *)GetProcAddress(lib, diversion->name);
        if (old_api == NULL)
        {
            fprintf(stderr, "unable to get pointer to %s\n", diversion->name);
            continue;
        }

        uint8_t *trampoline_api;
        if (hook_inline(old_api, diversion->new_sym, &trampoline_api) < 0)
        {
            fprintf(stderr, "hook_inline failed while hooking %s!%s\n",
                    diversion->lib, diversion->name);
            continue;
        }

        *diversion->old_sym = trampoline_api;
    }
}

#endif
