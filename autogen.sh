#!/bin/sh
OUT=Makefile.am
touch NEWS AUTHORS ChangeLog
echo > $OUT
cd src
PROGS=`echo *`
cd ..
COMMON=`echo common/*.cpp`
echo "bin_PROGRAMS = ${PROGS}" >>$OUT
echo "noinst_LIBRARIES = libcommon.a" >>$OUT
echo "libcommon_a_SOURCES = $COMMON" >>$OUT
echo "libcommon_a_CPPFLAGS = -Iinclude/" >>$OUT

for i in $PROGS ; do
	SOURCES=`echo src/$i/*.cpp`
	echo "${i}_SOURCES = $SOURCES" >>$OUT
	echo "${i}_CPPFLAGS = -Isrc/$i/ -Iinclude/" >>$OUT
	echo "${i}_LDADD = libcommon.a" >>$OUT
	echo "${i}_LDFLAGS = " >>$OUT #empty for future use.
	[ -f src/$i/Makefile.am.extra ] &&
		while read l ; do
			[ "$l" ] && echo "${i}_${l}" >>$OUT
		done < src/$i/Makefile.am.extra
done

aclocal && autoconf && automake --add-missing
