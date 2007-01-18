# $Id: configure.ac 98 2006-09-22 16:27:37Z sam $

AC_INIT(zzuf, 0.5)

AC_PREREQ(2.50)
AC_CONFIG_SRCDIR(src/zzuf.c)
AC_CONFIG_AUX_DIR(autotools)
AC_CANONICAL_SYSTEM

AM_INIT_AUTOMAKE(zzuf, 0.5)
AM_CONFIG_HEADER(config.h)

AM_PROG_CC_C_O
AC_PROG_CPP
AC_PROG_LIBTOOL

AC_CHECK_HEADERS(inttypes.h stdint.h getopt.h libc.h malloc.h dlfcn.h regex.h sys/socket.h sys/uio.h aio.h sys/mman.h sys/wait.h sys/resource.h)
AC_CHECK_FUNCS(open64 lseek64 mmap64 fopen64 fseeko _IO_getc getline getdelim __getdelim fgetln __srefill map_fd memalign posix_memalign aio_read accept socket readv pread recv recvfrom recvmsg mmap valloc sigaction)
AC_CHECK_TYPES(sighandler_t, [], [],
  [#define _GNU_SOURCE
   #include <signal.h>])
AC_CHECK_TYPES(sig_t, [], [],
  [#include <signal.h>])
AC_CHECK_TYPES(socklen_t, [], [],
  [#include <sys/types.h>
   #include <sys/socket.h>])

AC_MSG_CHECKING(for read() prototype)
AC_TRY_COMPILE([#include <unistd.h>],
 [ssize_t read(int fd, void *buf, size_t count);],
 [AC_MSG_RESULT(ssize_t read(... size_t);)
  AC_DEFINE(READ_USES_SSIZE_T, 1, [Define to 1 if read() uses ssize_t.])],
 [AC_MSG_RESULT(int read(... unsigned int);)])

AC_CHECK_FUNCS(getopt_long,
 [AC_DEFINE(HAVE_GETOPT_LONG, 1, Define to 1 if you have the `getopt_long' function.)],
 [AC_CHECK_LIB(gnugetopt, getopt_long,
   [AC_DEFINE(HAVE_GETOPT_LONG, 1, Define to 1 if you have the `getopt_long' function.)
    GETOPT_LIBS="${GETOPT_LIBS} -lgnugetopt"])])
AC_SUBST(GETOPT_LIBS)

AC_CHECK_LIB(m, log, [MATH_LIBS="-lm"])
AC_SUBST(MATH_LIBS)
AC_CHECK_LIB(dl, dlopen, [DL_LIBS="-ldl"])
AC_SUBST(DL_LIBS)

# Optimizations
CFLAGS="${CFLAGS} -g -O2 -fno-strength-reduce -fomit-frame-pointer"
# Code qui fait des warnings == code de porc == deux baffes dans ta gueule
CFLAGS="${CFLAGS} -Wall -W -Wpointer-arith -Wcast-align -Wcast-qual -Wstrict-prototypes -Wshadow -Waggregate-return -Wmissing-prototypes -Wnested-externs -Wsign-compare"

AC_OUTPUT([
  Makefile
  src/Makefile
  doc/Makefile
  test/Makefile
])

