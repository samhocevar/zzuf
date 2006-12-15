
bin_PROGRAMS = zzuf
zzuf_SOURCES = zzuf.c
zzuf_CPPFLAGS = -DLIBDIR=\"$(libdir)/zzuf\"

pkglib_LTLIBRARIES = libzzuf.la
libzzuf_la_SOURCES = libzzuf.c libzzuf.h fuzz.c fuzz.h debug.c debug.h preload.c preload.h random.c random.h
libzzuf_la_LDFLAGS = -module
libzzuf_la_LIBADD = -ldl

