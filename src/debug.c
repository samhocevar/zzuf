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

#if defined HAVE_STDINT_H
#   include <stdint.h>
#elif defined HAVE_INTTYPES_H
#   include <inttypes.h>
#endif
#include <stdio.h>
#if defined HAVE_UNISTD_H
#   include <unistd.h>
#endif
#if defined HAVE_IO_H
#   include <io.h>
#endif
#include <errno.h>
#include <stdarg.h>

#include "debug.h"
#include "libzzuf.h"

extern int _zz_debugfd;

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
        write(fd, b + 1, (int)(buf + 127 - b)); \
    } while(0)

void _zz_debug(char const *format, ...)
{
    static char const *hex2char = "0123456789abcdef";
    char const *f;
    va_list args;
    int saved_errno;

    if(_zz_debugfd < 0)
        return;

    saved_errno = errno;
    va_start(args, format);

#if 0
    /* This function's code is equivalent to the following *printf calls,
     * except it only uses signal-safe functions */
    fprintf(stderr, "** zzuf debug ** ");
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
#endif

    write(_zz_debugfd, "** zzuf debug ** ", 17);
    for(f = format; *f; f++)
    {
        if(*f != '%')
        {
            write(_zz_debugfd, f, 1);
            continue;
        }

        f++;
        if(!*f)
            break;

        if(*f == 'c')
        {
            char i = (char)(unsigned char)va_arg(args, int);
            if(i >= 0x20 && i < 0x7f)
                write(_zz_debugfd, &i, 1);
            else if(i == '\n')
                write(_zz_debugfd, "\\n", 2);
            else if(i == '\t')
                write(_zz_debugfd, "\\t", 2);
            else if(i == '\r')
                write(_zz_debugfd, "\\r", 2);
            else
            {
                write(_zz_debugfd, "\\x", 2);
                write(_zz_debugfd, hex2char + ((i & 0xf0) >> 4), 1);
                write(_zz_debugfd, hex2char + (i & 0x0f), 1);
            }
        }
        else if(*f == 'i' || *f == 'd')
        {
            int i = va_arg(args, int);
            WRITE_INT(_zz_debugfd, i, 10);
        }
        else if(*f == 'x')
        {
            int i = va_arg(args, int);
            WRITE_INT(_zz_debugfd, i, 16);
        }
        else if(f[0] == 'l' && (f[1] == 'i' || f[1] == 'd'))
        {
            long int i = va_arg(args, long int);
            WRITE_INT(_zz_debugfd, i, 10);
            f++;
        }
        else if(f[0] == 'l' && f[1] == 'l' && (f[2] == 'i' || f[1] == 'd'))
        {
            long long int i = va_arg(args, long long int);
            WRITE_INT(_zz_debugfd, i, 10);
            f += 2;
        }
        else if(f[0] == 'g')
        {
            double g = va_arg(args, double), h = 0.0000001;
            int i = g;
            WRITE_INT(_zz_debugfd, i, 10);
            for(i = 0; i < 7; i++)
            {
                g = (g - (int)g) * 10;
                h *= 10;
                if(g < h)
                    break;
                if(i == 0)
                    write(_zz_debugfd, ".", 1);
                write(_zz_debugfd, hex2char + (int)g, 1); 
            }
        }
        else if(f[0] == 'p')
        {
            uintptr_t i = va_arg(args, uintptr_t);
            if(!i)
                write(_zz_debugfd, "NULL", 5);
            else
            {
                write(_zz_debugfd, "0x", 2);
                WRITE_INT(_zz_debugfd, i, 16);
            }
        }
        else if(f[0] == 's')
        {
            char *s = va_arg(args, char *);
            if(!s)
                write(_zz_debugfd, "(nil)", 5);
            else
            {
                int l = 0;
                while(s[l])
                    l++;
                write(_zz_debugfd, s, l);
            }
        }
        else if(f[0] == '0' && f[1] == '2' && f[2] == 'x')
        {
            int i = va_arg(args, int);
            write(_zz_debugfd, hex2char + ((i & 0xf0) >> 4), 1);
            write(_zz_debugfd, hex2char + (i & 0x0f), 1);
            f += 2;
        }
        else
        {
            write(_zz_debugfd, f - 1, 2);
        }
    }
    write(_zz_debugfd, "\n", 1);
    va_end(args);
    errno = saved_errno;
}
