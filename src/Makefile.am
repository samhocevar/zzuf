# $Id$

COMMON = random.c random.h fd.c fd.h fuzz.c fuzz.h

bin_PROGRAMS = zzuf
zzuf_SOURCES = zzuf.c $(COMMON) opts.c opts.h md5.c md5.h timer.c timer.h
zzuf_CFLAGS = -DLIBDIR=\"$(libdir)/zzuf\"
zzuf_LDFLAGS = @MATH_LIBS@

pkglib_LTLIBRARIES = libzzuf.la
libzzuf_la_SOURCES = libzzuf.c libzzuf.h $(COMMON) debug.c debug.h \
                     lib-fd.c lib-mem.c lib-signal.c lib-stream.c lib-load.h
libzzuf_la_LDFLAGS = -avoid-version -no-undefined
libzzuf_la_LIBADD = @GETOPT_LIBS@ @DL_LIBS@ @MATH_LIBS@

