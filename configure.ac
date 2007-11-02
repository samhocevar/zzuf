# $Id: configure.ac 98 2006-09-22 16:27:37Z sam $

AC_INIT(zzuf, 0.9)

AC_PREREQ(2.50)
AC_CONFIG_SRCDIR(src/zzuf.c)
AC_CONFIG_AUX_DIR(autotools)
AC_CANONICAL_SYSTEM

AM_INIT_AUTOMAKE(zzuf, 0.9)
AM_CONFIG_HEADER(config.h)

AM_PROG_CC_C_O
AC_PROG_CPP
AC_PROG_LIBTOOL

case "${host_os}" in
  *mingw32*)
    DLL_LDFLAGS="-Wl,-l,imagehlp" # Trick libtool here
    WINSOCK2_LIBS="-lws2_32"
    ac_cv_func_recv=yes
    ac_cv_func_recvfrom=yes
    ac_cv_func_socket=yes
    ac_cv_func_accept=yes
    ac_cv_func_bind=yes
    ;;
esac
AC_SUBST(WINSOCK2_LIBS)
AC_SUBST(DLL_LDFLAGS)

AC_CHECK_HEADERS(windows.h winsock2.h io.h process.h unistd.h inttypes.h stdint.h getopt.h libc.h malloc.h dlfcn.h regex.h sys/socket.h sys/uio.h aio.h sys/mman.h sys/wait.h sys/resource.h sys/time.h endian.h)

AC_CHECK_FUNCS(setenv waitpid setrlimit gettimeofday fork kill pipe _pipe)
AC_CHECK_FUNCS(open64 lseek64 mmap64 fopen64 fseeko _IO_getc getline getdelim __getdelim fgetln __srefill map_fd memalign posix_memalign aio_read accept bind socket readv pread recv recvfrom recvmsg mmap valloc sigaction getpagesize)

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

AC_MSG_CHECKING(for recv() return value)
ac_v_recv_t="int"
AC_TRY_COMPILE([#include <sys/types.h>
  #include <sys/socket.h>],
 [ssize_t recv(int s, void *buf, size_t len, int flags);],
 [ac_v_recv_t="ssize_t"])
AC_MSG_RESULT($ac_v_recv_t)
AC_DEFINE_UNQUOTED(RECV_T, $ac_v_recv_t, [Define to the recv() return type])

ac_cv_have_getopt_long="no"
AC_CHECK_FUNCS(getopt_long,
 [ac_cv_have_getopt_long="yes"],
 [AC_CHECK_LIB(gnugetopt, getopt_long,
   [ac_cv_have_getopt_long="yes"
    GETOPT_LIBS="${GETOPT_LIBS} -lgnugetopt"])])
if test "$ac_cv_have_getopt_long" != "no"; then
  AC_DEFINE(HAVE_GETOPT_LONG, 1, Define to 1 if you have the `getopt_long' function.)
fi
AM_CONDITIONAL(NEED_GETOPT_LONG, test "$ac_cv_have_getopt_long" = "no")
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

