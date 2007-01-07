# $Id: configure.ac 98 2006-09-22 16:27:37Z sam $

AC_INIT(zzuf, 0.3)

AC_PREREQ(2.50)
AC_CONFIG_SRCDIR(src/zzuf.c)
AC_CONFIG_AUX_DIR(autotools)
AC_CANONICAL_SYSTEM

AM_INIT_AUTOMAKE(zzuf, 0.3)
AM_CONFIG_HEADER(config.h)

AM_PROG_CC_C_O
AC_PROG_CPP
AC_PROG_LIBTOOL

AC_CHECK_HEADERS(inttypes.h stdint.h getopt.h)
AC_CHECK_FUNCS(open64 lseek64 mmap64 fopen64 fseeko _IO_getc getline getdelim __getdelim fgetln __srefill)
AC_CHECK_TYPES(sighandler_t, [], [],
  [#define _GNU_SOURCE
   #include <signal.h>])
AC_CHECK_TYPES(sig_t, [], [],
  [#include <signal.h>])

AC_CHECK_FUNCS(getopt_long,
 [AC_DEFINE(HAVE_GETOPT_LONG, 1, Define to 1 if you have the `getopt_long' function.)],
 [AC_CHECK_LIB(gnugetopt, getopt_long,
   [AC_DEFINE(HAVE_GETOPT_LONG, 1, Define to 1 if you have the `getopt_long' function.)
    GETOPT_LIBS="${GETOPT_LIBS} -lgnugetopt"])])
AC_SUBST(GETOPT_LIBS)

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

