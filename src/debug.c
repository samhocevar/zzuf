/*
 *  zzuf - general purpose fuzzer
 *  Copyright (c) 2006 Sam Hocevar <sam@zoy.org>
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
 *  debug.c: debugging support
 */

#include "config.h"

/* Do we want our debug() call to be safe wrt. signals? */
#define SAFE_FUNCTION

#if defined HAVE_STDINT_H
#   include <stdint.h>
#elif defined HAVE_INTTYPES_H
#   include <inttypes.h>
#endif
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>

#include "debug.h"
#include "libzzuf.h"

extern int _zz_hasdebug;

#define WRITE_INT(fd, i, base) \
    do \
    { \
        char buf[128], *b = buf + 127; \
        if(i <= 0) \
            write(fd, (i = -i) ? "-" : "0", 1); /* XXX: hack here */ \
        while(i) \
        { \
            *b-- = hex2char[i % base]; \
            i /= base; \
        } \
        write(fd, b + 1, buf + 127 - b); \
    } while(0)

void _zz_debug(char const *format, ...)
{
#ifdef SAFE_FUNCTION
    static char const *hex2char = "0123456789abcdef";
    char const *f;
#endif
    va_list args;
    int saved_errno, fd = DEBUG_FILENO;

    if(!_zz_hasdebug)
        return;

    saved_errno = errno;
    va_start(args, format);
#ifdef SAFE_FUNCTION
    write(fd, "** zzuf debug ** ", 17);
    for(f = format; *f; f++)
    {
        if(*f != '%')
        {
            write(fd, f, 1);
            continue;
        }

        f++;
        if(!*f)
            break;

        if(*f == 'c')
        {
            char i = (char)(unsigned char)va_arg(args, int);
            if(i >= 0x20 && i < 0x7f)
                write(fd, &i, 1);
            else if(i == '\n')
                write(fd, "\\n", 2);
            else if(i == '\t')
                write(fd, "\\t", 2);
            else if(i == '\r')
                write(fd, "\\r", 2);
            else
            {
                write(fd, "\\x", 2);
                write(fd, hex2char + ((i & 0xf0) >> 4), 1);
                write(fd, hex2char + (i & 0x0f), 1);
            }
        }
        else if(*f == 'i')
        {
            int i = va_arg(args, int);
            WRITE_INT(fd, i, 10);
        }
        else if(f[0] == 'l' && f[1] == 'i')
        {
            long int i = va_arg(args, long int);
            WRITE_INT(fd, i, 10);
            f++;
        }
        else if(f[0] == 'l' && f[1] == 'l' && f[2] == 'i')
        {
            long long int i = va_arg(args, long long int);
            WRITE_INT(fd, i, 10);
            f += 2;
        }
        else if(f[0] == 'p')
        {
            uintptr_t i = va_arg(args, uintptr_t);
            if(!i)
                write(fd, "NULL", 5);
            else
            {
                write(fd, "0x", 2);
                WRITE_INT(fd, i, 16);
            }
        }
        else if(f[0] == 's')
        {
            char *s = va_arg(args, char *);
            if(!s)
                write(fd, "(nil)", 5);
            else
            {
                int l = 0;
                while(s[l])
                    l++;
                write(fd, s, l);
            }
        }
        else if(f[0] == '0' && f[1] == '2' && f[2] == 'x')
        {
            int i = va_arg(args, int);
            write(fd, hex2char + ((i & 0xf0) >> 4), 1);
            write(fd, hex2char + (i & 0x0f), 1);
            f += 2;
        }
        else
        {
            write(fd, f - 1, 2);
        }
    }
    write(fd, "\n", 1);
#else
    fprintf(stderr, "** zzuf debug ** ");
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
#endif
    va_end(args);
    errno = saved_errno;
}

