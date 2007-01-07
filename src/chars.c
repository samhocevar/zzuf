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
 *  chars.c: protected/refused characters
 */

#include "config.h"

#if defined HAVE_STDINT_H
#   include <stdint.h>
#elif defined HAVE_INTTYPES_H
#   include <inttypes.h>
#endif
#include <string.h>

#include "libzzuf.h"
#include "chars.h"

void _zz_readchars(int *table, char const *list)
{
    static char const hex[] = "0123456789abcdef0123456789ABCDEF";
    char const *tmp;
    int a, b;

    memset(table, 0, 256 * sizeof(int));

    for(tmp = list, a = b = -1; *tmp; tmp++)
    {
        int new;

        if(*tmp == '\\' && tmp[1] == '\0')
            new = '\\';
        else if(*tmp == '\\')
        {
            tmp++;
            if(*tmp == 'n')
                new = '\n';
            else if(*tmp == 'r')
                new = '\r';
            else if(*tmp == 't')
                new = '\t';
            else if(tmp[0] >= '0' && tmp[0] <= '7' && tmp[1] >= '0'
                     && tmp[1] <= '7' && tmp[2] >= '0' && tmp[2] <= '7')
            {
                new = tmp[2] - '0';
                new |= (int)(tmp[1] - '0') << 3;
                new |= (int)(tmp[0] - '0') << 6;
                tmp += 2;
            }
            else if((*tmp == 'x' || *tmp == 'X')
                     && tmp[1] && strchr(hex, tmp[1])
                     && tmp[2] && strchr(hex, tmp[2]))
            {
                new = ((strchr(hex, tmp[1]) - hex) & 0xf) << 4;
                new |= (strchr(hex, tmp[2]) - hex) & 0xf;
                tmp += 2;
            }
            else
                new = (unsigned char)*tmp; /* XXX: OK for \\, but what else? */
        }
        else
            new = (unsigned char)*tmp;

        if(a != -1 && b == '-' && a <= new)
        {
            while(a <= new)
                table[a++] = 1;
            a = b = -1;
        }
        else
        {
            if(a != -1)
                table[a] = 1;
            a = b;
            b = new;
        }
    }

    if(a != -1)
        table[a] = 1;
    if(b != -1)
        table[b] = 1;
}

