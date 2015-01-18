
bin_PROGRAMS = zzuf zzat
pkglib_LTLIBRARIES = libzzuf.la

ZZUF = \
    zzuf.c opts.c opts.h timer.c timer.h myfork.c myfork.h \
    util/getopt.c util/getopt.h util/md5.c util/md5.h \
    util/hex.c util/hex.h

ZZAT = \
    zzat.c \
    util/getopt.c util/getopt.h

LIBZZUF = \
    libzzuf/libzzuf.c libzzuf/libzzuf.h \
    libzzuf/debug.c libzzuf/debug.h \
    libzzuf/sys.c libzzuf/sys.h \
    libzzuf/network.c libzzuf/network.h \
    libzzuf/lib-fd.c libzzuf/lib-mem.c libzzuf/lib-signal.c \
    libzzuf/lib-stream.c libzzuf/lib-win32.c libzzuf/lib-load.h

COMMON = \
    common/common.h \
    common/random.c common/random.h \
    common/ranges.c common/ranges.h \
    common/fd.c common/fd.h \
    common/fuzz.c common/fuzz.h \
    util/mutex.h

EXTRA_DIST = \
    util/regex.cpp util/regex.h

zzuf_SOURCES = $(ZZUF) $(COMMON)
zzuf_CFLAGS = -DLIBDIR=\"$(libdir)/zzuf\" -I$(srcdir)/common
zzuf_LDFLAGS = $(MATH_LIBS) $(WINSOCK2_LIBS)
zzuf_DEPENDENCIES = libzzuf.la

zzat_SOURCES = $(ZZAT)
zzat_LDFLAGS =

libzzuf_la_SOURCES = $(LIBZZUF) $(COMMON)
libzzuf_la_CFLAGS = -DLIBZZUF -I$(srcdir)/libzzuf -I$(srcdir)/common
libzzuf_la_LDFLAGS = -avoid-version -no-undefined $(DLL_LDFLAGS)
libzzuf_la_LIBADD = $(DL_LIBS) $(MATH_LIBS) $(WINSOCK2_LIBS)

echo-sources: ; echo $(SOURCES)

