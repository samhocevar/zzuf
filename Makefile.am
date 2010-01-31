
SUBDIRS = src test doc
DIST_SUBDIRS = $(SUBDIRS)

EXTRA_DIST = bootstrap AUTHORS \
	m4/cflags.m4 m4/func.m4 \
	msvc/config.h \
	msvc/libzzuf.vcproj msvc/libzzuf.vcxproj \
	msvc/zznop.vcxproj \
	msvc/zzuf10.sln msvc/zzuf.sln \
	msvc/zzuf.vcproj msvc/zzuf.vcxproj
ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS = foreign dist-bzip2

update-changelog: FORCE
	git --help >/dev/null 2>&1 \
	  && test -d .git \
	  && git log --stat | grep -v '^    \(git-svn-id\|$$\)' \
	      | sed '/^Author:/s/ <.*@.*>//' > ChangeLog

FORCE:
