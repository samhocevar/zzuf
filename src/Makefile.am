# $Id$

COMMON = random.c random.h ranges.c ranges.h fd.c fd.h fuzz.c fuzz.h
if NEED_GETOPT_LONG
GETOPT = mygetopt.c mygetopt.h
endif

bin_PROGRAMS = zzuf
zzuf_SOURCES = zzuf.c $(COMMON) $(GETOPT) \
               opts.c opts.h md5.c md5.h timer.c timer.h
zzuf_CFLAGS = -DLIBDIR=\"$(libdir)/zzuf\" -DSONAME=\"$$(grep dlname libzzuf.la | cut -f2 -d"'")\"
zzuf_LDFLAGS = $(MATH_LIBS) $(WINSOCK2_LIBS)
zzuf_DEPENDENCIES = libzzuf.la

pkglib_LTLIBRARIES = libzzuf.la
libzzuf_la_SOURCES = libzzuf.c libzzuf.h $(COMMON) debug.c debug.h sys.c sys.h \
                     lib-fd.c lib-mem.c lib-signal.c lib-stream.c lib-load.h
libzzuf_la_CFLAGS = -DLIBZZUF
libzzuf_la_LDFLAGS = -avoid-version -no-undefined $(DLL_LDFLAGS)
libzzuf_la_LIBADD = $(GETOPT_LIBS) $(DL_LIBS) $(MATH_LIBS) $(WINSOCK2_LIBS)

