/*
 *  zzuf - general purpose fuzzer
 *  Copyright (c) 2006-2009 Sam Hocevar <sam@hocevar.net>
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

#define ATTRIBUTE_PRINTF(x,y) /* */
#define CONNECT_USES_STRUCT_SOCKADDR 1
#define FPOS_CAST(x) (x)
#define HAVE_ACCEPT 1
/* #undef HAVE_AIO_H */
/* #undef HAVE_AIO_READ */
/* #undef HAVE_ARPA_INET_H */
#define HAVE_BIND 1
#define HAVE_CONNECT 1
/* #undef HAVE_DLFCN_H */
#define HAVE_DUP 1
#define HAVE_DUP2 1
/* #undef HAVE_ENDIAN_H */
/* #undef HAVE_FGETC_UNLOCKED */
/* #undef HAVE_FGETLN */
/* #undef HAVE_FGETS_UNLOCKED */
#define HAVE_FOPEN64 1
/* #undef HAVE_FORK */
/* #undef HAVE_FREAD_UNLOCKED */
/* #undef HAVE_FREEBSD_FILE */
/* #undef HAVE_FREOPEN64 */
/* #undef HAVE_FSEEKO */
/* #undef HAVE_FSEEKO64 */
/* #undef HAVE_FSETPOS64 */
/* #undef HAVE_FTELLO */
/* #undef HAVE_FTELLO64 */
/* #undef HAVE_GETCHAR_UNLOCKED */
/* #undef HAVE_GETC_UNLOCKED */
/* #undef HAVE_GETDELIM */
/* #undef HAVE_GETLINE */
/* #undef HAVE_GETOPT_H */
/* #undef HAVE_GETOPT_LONG */
#define HAVE_GETPAGESIZE 1
/* #undef HAVE_GETTIMEOFDAY */
/* #undef HAVE_GLIBC_FILE */
#define HAVE_INTTYPES_H 1
#define HAVE_IO_H 1
/* #undef HAVE_KILL */
/* #undef HAVE_LIBC_H */
/* #undef HAVE_LSEEK64 */
/* #undef HAVE_MACH_TASK_H */
#define HAVE_MALLOC_H 1
/* #undef HAVE_MAP_FD */
/* #undef HAVE_MEMALIGN */
#define HAVE_MEMORY_H 1
/* #undef HAVE_MMAP */
/* #undef HAVE_MMAP64 */
/* #undef HAVE_NETINET_IN_H */
/* #undef HAVE_OPEN64 */
/* #undef HAVE_PIPE */
/* #undef HAVE_POSIX_MEMALIGN */
#define HAVE_PRAGMA_INIT 1
/* #undef HAVE_PREAD */
#define HAVE_PROCESS_H 1
/* #undef HAVE_READV */
#define HAVE_RECV 1
#define HAVE_RECVFROM 1
/* #undef HAVE_RECVMSG */
/* #undef HAVE_REGEX_H */
/* #undef HAVE_SETENV */
/* #undef HAVE_SETRLIMIT */
/* #undef HAVE_SIGACTION */
/* #undef HAVE_SIGHANDLER_T */
/* #undef HAVE_SIG_T */
#define HAVE_SOCKET 1
/* #undef HAVE_SOCKLEN_T */
/* #undef HAVE_SOLARIS_FILE */
#define HAVE_STDINT_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STRINGS_H 1
#define HAVE_STRING_H 1
/* #undef HAVE_SYS_CDEFS_H */
/* #undef HAVE_SYS_MMAN_H */
/* #undef HAVE_SYS_RESOURCE_H */
/* #undef HAVE_SYS_SOCKET_H */
#define HAVE_SYS_STAT_H 1
/* #undef HAVE_SYS_TIME_H */
#define HAVE_SYS_TYPES_H 1
/* #undef HAVE_SYS_UIO_H */
/* #undef HAVE_SYS_WAIT_H */
/* #undef HAVE_UNISTD_H */
/* #undef HAVE_VALLOC */
/* #undef HAVE_WAITPID */
#define HAVE_WINDOWS_H 1
#define HAVE_WINSOCK2_H 1
/* #undef HAVE__IO_GETC */
#define HAVE__PIPE 1
/* #undef HAVE___FILBUF */
/* #undef HAVE___FOPEN64 */
/* #undef HAVE___FREOPEN64 */
/* #undef HAVE___FSEEKO64 */
/* #undef HAVE___FSETPOS64 */
/* #undef HAVE___FTELLO64 */
/* #undef HAVE___GETDELIM */
/* #undef HAVE___LSEEK64 */
/* #undef HAVE___OPEN64 */
/* #undef HAVE___SREFILL */
/* #undef HAVE___SRGET */
/* #undef HAVE___UFLOW */
#define LT_OBJDIR ""
/* #undef NO_MINUS_C_MINUS_O */
#define PACKAGE_BUGREPORT ""
#define PACKAGE_NAME "zzuf"
#define PACKAGE_STRING "zzuf 0.12"
#define PACKAGE_TARNAME "zzuf"
#define PACKAGE_URL ""
#define PACKAGE_VERSION "0.12"
/* #undef READ_USES_SSIZE_T */
#define RECV_T int
#define SONAME "libzzuf.dll"
#define STDC_HEADERS 1
/* #undef __func__ */

/* Fucking Visual Studio should just shut the fuck up with this fucking
 * warning about fucking ISO C++ when we fucking compile fucking C. */
#pragma warning(disable: 4996)

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
#define __func__ __FUNCTION__

#define STDOUT_FILENO 1
#define STDERR_FILENO 2
