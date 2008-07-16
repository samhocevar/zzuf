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

AC_CHECK_HEADERS(windows.h winsock2.h io.h process.h unistd.h inttypes.h stdint.h getopt.h libc.h malloc.h dlfcn.h regex.h sys/cdefs.h sys/socket.h netinet/in.h sys/uio.h aio.h sys/mman.h sys/wait.h sys/resource.h sys/time.h endian.h)

AC_CHECK_FUNCS(setenv waitpid setrlimit gettimeofday fork kill pipe _pipe)
AC_CHECK_FUNCS(open64 __open64 lseek64 __lseek64 mmap64 fopen64 __fopen64 __freopen64 dup dup2 fseeko __fseeko64 __fsetpos64 _IO_getc getline getdelim __getdelim fgetln __srefill __filbuf map_fd memalign posix_memalign aio_read accept bind connect socket readv pread recv recvfrom recvmsg mmap valloc sigaction getpagesize getc_unlocked getchar_unlocked fgetc_unlocked fread_unlocked fgets_unlocked)

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

AC_MSG_CHECKING(for pragma INIT/FINI)
AC_TRY_COMPILE([],
 [#pragma INIT "my_init"
  void my_init(void)],
 [AC_MSG_RESULT(yes)
  AC_DEFINE(HAVE_PRAGMA_INIT, 1, [Define to 1 if you have pragma INIT])],
 [AC_MSG_RESULT(no)])

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

