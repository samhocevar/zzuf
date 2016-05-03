
AC_INIT(zzuf, 0.15)
AC_CONFIG_AUX_DIR(.auto)
AM_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE([subdir-objects no-define tar-ustar silent-rules])

AC_PREREQ(2.50)

AM_PROG_CC_C_O
AC_PROG_CPP
AC_PROG_LIBTOOL

dnl AC_PROG_EGREP only exists in autoconf 2.54+, so we use AC_EGREP_CPP right
dnl now otherwise it might be set in an obscure if statement. Same thing for
dnl PKG_PROG_PKG_CONFIG which needs to be called first.
AC_EGREP_CPP(yes, foo)
PKG_PROG_PKG_CONFIG()

dnl Don't let pkg-config fuck our cross-compilation environment
m4_pattern_allow([^PKG_CONFIG_LIBDIR$])
if test "$build" != "$host" -a "${PKG_CONFIG_LIBDIR}" = ""; then
  export PKG_CONFIG_LIBDIR=/dev/null
fi

AC_C_INLINE
AC_C_FUNC

# C99 support (mandatory)
AC_TRY_CFLAGS(-std=c99,
 [CFLAGS="${CFLAGS} -std=c99"],
 [AC_MSG_ERROR(support for C99 (-std=c99) required)])

# Library suffix
AC_MSG_CHECKING(for libzzuf full name)
case "$shrext_cmds" in
  "") SONAME="libzzuf.so" ;;
  *) eval SONAME="libzzuf$shrext_cmds" ;;
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
    # This one is necessary if we want inet_pton() with mingw
    AC_DEFINE(_WIN32_WINNT, 0x600, [Define the Windows version to Vista])
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

AC_CHECK_HEADERS(unistd.h inttypes.h stdint.h endian.h libc.h)
AC_CHECK_HEADERS(windows.h winsock2.h process.h)
AC_CHECK_HEADERS(malloc.h dlfcn.h regex.h sys/cdefs.h sys/socket.h)
AC_CHECK_HEADERS(netinet/in.h arpa/inet.h sys/uio.h aio.h)
AC_CHECK_HEADERS(sys/mman.h sys/wait.h sys/resource.h sys/time.h)
AC_CHECK_HEADERS(io.h mach/task.h)

AC_CHECK_FUNCS(setenv waitpid setrlimit gettimeofday fork kill pipe _pipe)
AC_CHECK_FUNCS(regexec regwexec)
AC_CHECK_FUNCS(dup dup2 ftello fseeko _IO_getc getline getdelim fgetln map_fd)
AC_CHECK_FUNCS(memalign posix_memalign aio_read accept bind connect socket)
AC_CHECK_FUNCS(readv pread recv recvfrom recvmsg valloc sigaction)
AC_CHECK_FUNCS(mmap getpagesize)
AC_CHECK_FUNCS(getc_unlocked getchar_unlocked fgetc_unlocked fread_unlocked fgets_unlocked)
AC_CHECK_FUNCS(__getdelim __srefill __filbuf __srget __uflow)
AC_CHECK_FUNCS(open64 lseek64 mmap64 fopen64 freopen64 ftello64 fseeko64 fsetpos64)
AC_CHECK_FUNCS(__open64 __lseek64 __fopen64 __freopen64 __ftello64 __fseeko64 __fsetpos64)
AC_CHECK_FUNCS(__fgets_chk __fgets_unlocked_chk __fread_chk __fread_unlocked_chk __read_chk __recv_chk __recvfrom_chk)
AC_CHECK_FUNCS(CreateFileA CreateFileW ReOpenFile ReadFile CloseHandle)
AC_CHECK_FUNCS(AllocConsole AttachConsole SetConsoleMode WriteConsoleOutputA WriteConsoleOutputW)

AC_CHECK_TYPES(sighandler_t, [], [],
  [#define _GNU_SOURCE
   #include <signal.h>])
AC_CHECK_TYPES(sig_t, [], [],
  [#include <signal.h>])
AC_CHECK_TYPES(socklen_t, [], [],
  [#include <sys/types.h>
   #include <sys/socket.h>])
AC_CHECK_TYPES(fpos64_t, [], [],
  [#define _LARGEFILE64_SOURCE
   #define _LARGEFILE_SOURCE
   #include <stdio.h>])

AC_MSG_CHECKING(for connect() second argument)
AC_TRY_COMPILE([#include <sys/types.h>
                #include <sys/socket.h>],
 [#if defined HAVE_SOCKLEN_T
  int connect(int, const struct sockaddr *, socklen_t);
  #else
  int connect(int, const struct sockaddr *, int);
  #endif],
 [AC_MSG_RESULT(const struct sockaddr *)
  AC_DEFINE(CONNECT_USES_STRUCT_SOCKADDR, 1, [Define to 1 if connect() uses struct sockaddr.])],
 [AC_MSG_RESULT(const void *)])

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

AC_MSG_CHECKING([for _IO_read_ptr and _IO_read_end in FILE (glibc-style)])
AC_TRY_COMPILE([#include <stdio.h>],
 [FILE *fp; fp->_IO_read_ptr++; fp->_IO_read_end++],
 [ac_cv_have_glibc_file=yes],
 [ac_cv_have_glibc_file=no])
AC_MSG_RESULT($ac_cv_have_glibc_file)
if test "$ac_cv_have_glibc_file" != "no"; then
  AC_DEFINE(HAVE_GLIBC_FILE, 1, [Define to 1 if FILE has glibc-style members])
fi

AC_MSG_CHECKING([for _bf._base, _r and _p in FILE (FreeBSD-style)])
AC_TRY_COMPILE([#include <stdio.h>],
 [FILE *fp; fp->_bf._base++; fp->_r++; fp->_p++],
 [ac_cv_have_freebsd_file=yes],
 [ac_cv_have_freebsd_file=no])
AC_MSG_RESULT($ac_cv_have_freebsd_file)
if test "$ac_cv_have_freebsd_file" != "no"; then
  AC_DEFINE(HAVE_FREEBSD_FILE, 1, [Define to 1 if FILE has FreeBSD-style members])
fi

AC_MSG_CHECKING([for _base, _cnt and _ptr in FILE (Solaris-style)])
AC_TRY_COMPILE([#include <stdio.h>],
 [FILE *fp; fp->_base++; fp->_cnt++; fp->_ptr++],
 [ac_cv_have_solaris_file=yes],
 [ac_cv_have_solaris_file=no])
AC_MSG_RESULT($ac_cv_have_solaris_file)
if test "$ac_cv_have_solaris_file" != "no"; then
  AC_DEFINE(HAVE_SOLARIS_FILE, 1, [Define to 1 if FILE has Solaris-style members])
fi

dnl  On HP-UX, fpos64_t == int64_t, but on Linux it's a compound object.
AC_MSG_CHECKING(how to access fpos64_t x)
ac_v_fpos64_t="unknown"
AC_TRY_COMPILE(
 [#define _LARGEFILE64_SOURCE
  #define _LARGEFILE_SOURCE
  #include <stdio.h>],
 [fpos64_t x; long long int y = x.__pos;],
 [ac_v_fpos64_t="(x).__pos"])
AC_TRY_COMPILE(
 [#define _LARGEFILE64_SOURCE
  #define _LARGEFILE_SOURCE
  #include <stdio.h>],
 [fpos64_t x; long long int y = (long long int)x;],
 [ac_v_fpos64_t="(x)"])
AC_MSG_RESULT($ac_v_fpos64_t)
AC_DEFINE_UNQUOTED(FPOS64_CAST(x), $ac_v_fpos64_t, [Define to a macro for accessing an fpos64_t variable])

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

AC_CHECK_LIB(dl, dladdr,
 [AC_DEFINE(HAVE_DLADDR, 1, Define to 1 if you have the `dladdr' function.)])

AC_CHECK_LIB(m, log, [MATH_LIBS="-lm"])
AC_SUBST(MATH_LIBS)
AC_CHECK_LIB(dl, dlopen, [DL_LIBS="-ldl"])
AC_SUBST(DL_LIBS)

AC_CONFIG_FILES([
  Makefile
  src/Makefile
  doc/Makefile
  test/Makefile
])
AC_CONFIG_FILES([
  doc/zzat.1
  doc/zzuf.1
  doc/libzzuf.3
])
AC_OUTPUT

