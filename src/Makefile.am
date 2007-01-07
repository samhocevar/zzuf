COMMON = random.c random.h fd.c fd.h fuzz.c fuzz.h

bin_PROGRAMS = zzuf
zzuf_SOURCES = zzuf.c $(COMMON)
zzuf_CFLAGS = -DLIBDIR=\"$(libdir)/zzuf\"

pkglib_LTLIBRARIES = libzzuf.la
libzzuf_la_SOURCES = libzzuf.c libzzuf.h $(COMMON) debug.c debug.h \
                     load-fd.c load-signal.c load-stream.c load.h
libzzuf_la_LDFLAGS = -avoid-version -no-undefined
libzzuf_la_LIBADD = @GETOPT_LIBS@ @DL_LIBS@

