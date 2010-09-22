
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

update-changelog: FORCE
	git --help >/dev/null 2>&1 \
	  && test -d .git \
	  && git log --stat | awk 'function flush() { if (m != "") { print "Commit: " v "\nAuthor: " a m } m=""; v="UNSUBMITTED" } { if ($$1 == "commit") flush(); else if ($$1 == "Author:") { a = $$2 } else if ($$1 == "git-svn-id:") { split($$2,tmp,"@"); v=tmp[2] } else if ($$_ != "    ") { m=m "\n" $$_ } } END { flush() }' > ChangeLog

echo-dirs: ; echo src test

FORCE:
