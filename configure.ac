# $Id: configure.ac 98 2006-09-22 16:27:37Z sam $

AC_INIT(zzuf, 0.12)
AC_CONFIG_AUX_DIR(.auto)
AM_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE([no-define tar-ustar])

AC_PREREQ(2.50)

AM_PROG_CC_C_O
AC_PROG_CPP
AC_PROG_LIBTOOL

AC_C_INLINE
AC_C_FUNC

# Library suffix
AC_MSG_CHECKING(for libzzuf full name)
case "$shrext_cmds" in
  "") SONAME="libzzuf.so" ;;
  *) SONAME="libzzuf$shrext_cmds" ;;
esac
AC_MSG_RESULT($SONAME)
AC_DEFINE_UNQUOTED(SONAME, "$SONAME", [Define to the libzzuf full name])

# Optimizations
AC_TRY_CFLAGS(-g -O2, CFLAGS="${CFLAGS} -g -O2")
# Code qui fait des warnings == code de porc == deux baffes dans ta gueule
AC_TRY_CFLAGS(-Wall, CFLAGS="${CFLAGS} -Wall")
AC_TRY_CFLAGS(-W, CFLAGS="${CFLAGS} -W")
AC_TRY_CFLAGS(-Wpointer-arith -Wcast-align -Wcast-qual -Wstrict-prototypes -Wshadow -Waggregate-return -Wmissing-prototypes -Wnested-externs -Wsign-compare, CFLAGS="${CFLAGS} -Wpointer-arith -Wcast-align -Wcast-qual -Wstrict-prototypes -Wshadow -Waggregate-return -Wmissing-prototypes -Wnested-externs -Wsign-compare")

case "${host_os}" in
  *mingw32*)
    DLL_LDFLAGS="-Wl,-l,imagehlp" # Trick libtool here
    WINSOCK2_LIBS="-lws2_32"
    ac_cv_func_recv=yes
    ac_cv_func_recvfrom=yes
    ac_cv_func_socket=yes
    ac_cv_func_accept=yes
    ac_cv_func_bind=yes
    ac_cv_func_connect=yes
    ;;
esac
AC_SUBST(WINSOCK2_LIBS)
AC_SUBST(DLL_LDFLAGS)

AC_CHECK_HEADERS(windows.h winsock2.h io.h process.h unistd.h inttypes.h stdint.h getopt.h libc.h malloc.h dlfcn.h regex.h sys/cdefs.h sys/socket.h netinet/in.h arpa/inet.h sys/uio.h aio.h sys/mman.h sys/wait.h sys/resource.h sys/time.h endian.h)

AC_CHECK_FUNCS(setenv waitpid setrlimit gettimeofday fork kill pipe _pipe)
AC_CHECK_FUNCS(open64 __open64 lseek64 __lseek64 mmap64 fopen64 __fopen64 freopen64 __freopen64 dup dup2 fseeko fseeko64 __fseeko64 fsetpos64 __fsetpos64 _IO_getc getline getdelim __getdelim fgetln __srefill __filbuf __srget __uflow map_fd memalign posix_memalign aio_read accept bind connect socket readv pread recv recvfrom recvmsg mmap valloc sigaction getpagesize getc_unlocked getchar_unlocked fgetc_unlocked fread_unlocked fgets_unlocked)

AC_CHECK_TYPES(sighandler_t, [], [],
  [#define _GNU_SOURCE
   #include <signal.h>])
AC_CHECK_TYPES(sig_t, [], [],
  [#include <signal.h>])
AC_CHECK_TYPES(socklen_t, [], [],
  [#include <sys/types.h>
   #include <sys/socket.h>])

AC_MSG_CHECKING(for read() prototype)
AC_TRY_COMPILE([#define _INCLUDE_POSIX_SOURCE
                #include <unistd.h>],
 [ssize_t read(int fd, void *buf, size_t count);],
 [AC_MSG_RESULT(ssize_t read(... size_t);)
  AC_DEFINE(READ_USES_SSIZE_T, 1, [Define to 1 if read() uses ssize_t.])],
 [AC_MSG_RESULT(int read(... unsigned int);)])

AC_MSG_CHECKING(for recv() return value)
ac_v_recv_t="int"
AC_TRY_COMPILE([#define _XOPEN_SOURCE_EXTENDED
                #include <sys/types.h>
                #include <sys/socket.h>],
 [ssize_t recv(int s, void *buf, size_t len, int flags);],
 [ac_v_recv_t="ssize_t"])
AC_MSG_RESULT($ac_v_recv_t)
AC_DEFINE_UNQUOTED(RECV_T, $ac_v_recv_t, [Define to the recv() return type])

AC_MSG_CHECKING(for FILE* internal members)
ac_cv_have_glibc_fp="no"
ac_v_fp_cnt="unknown"
ac_v_fp_ptr="unknown"
AC_TRY_COMPILE([#include <stdio.h>],
 [FILE *fp; fp->_IO_read_ptr++; fp->_IO_read_end++],
 [ac_cv_have_glibc_fp=yes; ac_v_fp_cnt=_IO_read_end; ac_v_fp_ptr=_IO_read_ptr],
 [AC_TRY_COMPILE([#include <stdio.h>],
   [FILE *fp; fp->__cnt++; fp->__ptr++],
   [ac_v_fp_cnt=__cnt; ac_v_fp_ptr=__ptr],
   [AC_TRY_COMPILE([#include <stdio.h>],
     [FILE *fp; fp->_cnt++; fp->_ptr++],
     [ac_v_fp_cnt=_cnt; ac_v_fp_ptr=_ptr],
     [AC_TRY_COMPILE([#include <stdio.h>],
       [FILE *fp; fp->_c++; fp->_p++],
       [ac_v_fp_cnt=_c; ac_v_fp_ptr=_p],
       [AC_TRY_COMPILE([#include <stdio.h>],
         [FILE *fp; fp->_r++; fp->_p++],
         [ac_v_fp_cnt=_r; ac_v_fp_ptr=_p])])])])])
AC_MSG_RESULT($ac_v_fp_ptr/$ac_v_fp_cnt)
if test "$ac_cv_have_glibc_fp" != "no"; then
  AC_DEFINE(HAVE_GLIBC_FP, 1, [Define to 1 if FILE has glibc-style members])
fi
AC_DEFINE_UNQUOTED(FILE_PTR, $ac_v_fp_ptr, [Define to the FILE::ptr member])
AC_DEFINE_UNQUOTED(FILE_CNT, $ac_v_fp_cnt, [Define to the FILE::cnt member])

dnl  On HP-UX, fpos64_t == int64_t, but on Linux it's a compound object.
AC_MSG_CHECKING(how to access fpos64_t x)
ac_v_fpos64_t="unknown"
AC_TRY_COMPILE(
 [#define _LARGEFILE64_SOURCE
  #include <stdio.h>],
 [fpos64_t x; long long int y = x.__pos;],
 [ac_v_fpos64_t="(x).__pos"])
AC_TRY_COMPILE(
 [#define _LARGEFILE64_SOURCE
  #include <stdio.h>],
 [fpos64_t x; long long int y = (long long int)x;],
 [ac_v_fpos64_t="(x)"])
AC_MSG_RESULT($ac_v_fpos64_t)
AC_DEFINE_UNQUOTED(FPOS_CAST(x), $ac_v_fpos64_t, [Define to a macro for accessing an fpos64_t variable])

AC_MSG_CHECKING(for pragma INIT/FINI)
AC_TRY_COMPILE([],
 [#pragma INIT "my_init"
  void my_init(void)],
 [AC_MSG_RESULT(yes)
  AC_DEFINE(HAVE_PRAGMA_INIT, 1, [Define to 1 if you have pragma INIT])],
 [AC_MSG_RESULT(no)])

AC_MSG_CHECKING(for __printf__ attribute)
ac_v_attribute_printf=""
AC_TRY_COMPILE([],
 [extern void foo(const char *, ...)
     __attribute__((__format__(__printf__, 1, 2)));],
 [AC_MSG_RESULT(yes)
  ac_v_attribute_printf="__attribute__((__format__(__printf__, x, y)))"],
 [AC_MSG_RESULT(no)])
AC_DEFINE_UNQUOTED(ATTRIBUTE_PRINTF(x,y), $ac_v_attribute_printf, [Define to the __printf__ attribute if present])

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

AC_OUTPUT([
  Makefile
  src/Makefile
  doc/Makefile
  test/Makefile
])

