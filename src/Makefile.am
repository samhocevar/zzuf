
bin_PROGRAMS = zzuf zzcat
pkglib_LTLIBRARIES = libzzuf.la

ZZUF = \
    zzuf.c opts.c opts.h md5.c md5.h timer.c timer.h myfork.c myfork.h

ZZCAT = \
    zzcat.c

LIBZZUF = \
    libzzuf/libzzuf.c libzzuf/libzzuf.h \
    libzzuf/debug.c libzzuf/debug.h \
    libzzuf/sys.c libzzuf/sys.h \
    libzzuf/network.c libzzuf/network.h \
    libzzuf/lib-fd.c libzzuf/lib-mem.c libzzuf/lib-signal.c \
    libzzuf/lib-stream.c libzzuf/lib-load.h

COMMON = \
    common/common.h \
    common/random.c common/random.h \
    common/ranges.c common/ranges.h \
    common/fd.c common/fd.h \
    common/fuzz.c common/fuzz.h

if NEED_GETOPT_LONG
GETOPT = mygetopt.c mygetopt.h
endif

zzuf_SOURCES = $(ZZUF) $(COMMON) $(GETOPT)
zzuf_CFLAGS = -DLIBDIR=\"$(libdir)/zzuf\" -I$(srcdir)/common
zzuf_LDFLAGS = $(MATH_LIBS) $(WINSOCK2_LIBS)
zzuf_DEPENDENCIES = libzzuf.la

zzcat_SOURCES = $(ZZCAT) $(GETOPT)

libzzuf_la_SOURCES = $(LIBZZUF) $(COMMON)
libzzuf_la_CFLAGS = -DLIBZZUF -I$(srcdir)/libzzuf -I$(srcdir)/common
libzzuf_la_LDFLAGS = -avoid-version -no-undefined $(DLL_LDFLAGS)
libzzuf_la_LIBADD = $(GETOPT_LIBS) $(DL_LIBS) $(MATH_LIBS) $(WINSOCK2_LIBS)

echo-sources: ; echo $(SOURCES)

