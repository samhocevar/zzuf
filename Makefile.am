
SUBDIRS = src test doc
DIST_SUBDIRS = $(SUBDIRS)

EXTRA_DIST = bootstrap build-osx build-win32 AUTHORS \
	m4/cflags.m4 m4/func.m4 \
	msvc/config.h \
	msvc/libzzuf.vcxproj \
	msvc/zzat.vcxproj \
	msvc/zznop.vcxproj \
	msvc/zzuf.vcxproj \
	msvc/zzuf.sln
ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS = foreign dist-bzip2

# Travis CI uses “make test” instead of “make check”
test: check

echo-dirs: ; echo src test

FORCE:
