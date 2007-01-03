
bin_PROGRAMS = zzuf
zzuf_SOURCES = zzuf.c
AM_CPPFLAGS = -DLIBDIR=\"$(libdir)/zzuf\"

pkglib_LTLIBRARIES = libzzuf.la
libzzuf_la_SOURCES = libzzuf.c libzzuf.h fuzz.c fuzz.h debug.c debug.h \
                     load-fd.c load-signal.c load-stream.c load.h \
                     random.c random.h
libzzuf_la_LDFLAGS = -avoid-version -no-undefined
libzzuf_la_LIBADD = -ldl

