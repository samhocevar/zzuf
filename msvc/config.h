/*
 *  zzuf - general purpose fuzzer
 *  Copyright (c) 2006, 2007 Sam Hocevar <sam@zoy.org>
 *                All Rights Reserved
 *
 *  $Id: timer.h 192 2007-01-12 15:47:48Z sam $
 *
 *  This program is free software. It comes without any warranty, to
 *  the extent permitted by applicable law. You can redistribute it
 *  and/or modify it under the terms of the Do What The Fuck You Want
 *  To Public License, Version 2, as published by Sam Hocevar. See
 *  http://sam.zoy.org/wtfpl/COPYING for more details.
 */

/*
 *  config.h: MSVC-specific configuration file
 */

#define VERSION "0.7 (msvc)"
#define SONAME "libzzuf.dll"

#define HAVE_WINDOWS_H 1
#define HAVE_WINSOCK2_H 1
#define HAVE_IO_H 1
#define HAVE_PROCESS_H 1

#define HAVE__PIPE

/* Win32-specific, of course. */
typedef signed long long int int64_t;
typedef unsigned long long int uint64_t;
typedef signed int int32_t;
typedef unsigned int uint32_t;
typedef signed short int16_t;
typedef unsigned short uint16_t;
typedef signed char int8_t;
typedef unsigned char uint8_t;

#include <stddef.h> /* Has uintptr_t etc. */
typedef int pid_t;

#define inline /* undefined */
#define __attribute__(x) /* undefined */

#define STDOUT_FILENO 1
#define STDERR_FILENO 2
