##
##
## configure.ac for libpam-devid in /home/phil/Travail/Development/Pam/libpam-devid
##
## Made by Philippe THIERRY
## Login   <Philippe.THIERRY@thalesgroup.com>
##
## Started on  mer. 20 juin 2012 15:22:36 CEST Philippe THIERRY
## Last update mer. 20 juin 2012 15:22:36 CEST Philippe THIERRY
##


#############################################################################
## Preambule
#############################################################################
AC_INIT([pam-devid], [0.2], [philippe.thierry@thalesgroup.com], [Philippe THIERRY])
AM_INIT_AUTOMAKE([1.9.5 foreign dist-bzip2 no-dist-gzip foreign])
AC_CONFIG_SRCDIR([src/pam_devid.c])
AM_CONFIG_HEADER(src/config.h)
AM_MAINTAINER_MODE

#############################################################################
## Init source language configuration
#############################################################################
AC_LANG([C])

AC_ISC_POSIX
AC_PROG_CC
AM_PROG_CC_STDC
AM_PROG_LIBTOOL
AC_PROG_LN_S
AC_HEADER_STDC


#############################################################################
## Init static and shared lib support
#############################################################################
# support for static lib
AC_PROG_RANLIB

# FIXME : add shared lib support


#############################################################################
## Headers check
#############################################################################
AC_CHECK_HEADER([security/pam_modules.h],,AC_MSG_ERROR([Cannot find security/pam_modulesh ! Check your installation !]))

#############################################################################
## Libraries check
#############################################################################

#======== Libefence
AC_ARG_WITH(efence, [  --with-efence           Link with electric fence ])
if test "$with_efence" = "yes"
then
	AC_CHECK_LIB(efence, EF_ALIGNMENT, LIBS="${LIBS} -lefence", AC_MSG_ERROR(libefence not found))
        efence="yes";
        EFENCE=1;
else
	efence="no";
fi


#############################################################################
## Third part programs detection
#############################################################################

#======== Checking doxygen
AC_CHECK_PROG([DOXYGEN], [doxygen], [yes], [no])
if test $DOXYGEN = ":"; then
  AC_MSG_WARN([Unable to detect doxygen in your path. You will not be able \
  to generate 42sh developpement documentiation.], 2)
  doxygen="no";
else
  doxygen="yes";
fi

#======== Checking gprof
AC_CHECK_PROG([GPROF], [gprof], [yes], [no])
if test $GPROF = ":"; then
  AC_MSG_WARN([Unable to detect gprof in your path. You will not be able \
  to generate nfhcctl function calls profile.], 2)
  gprof="no";
else
  gprof="yes";
fi

#======== Checking gcov
AC_CHECK_PROG([GCOV], [gcov], [yes], [no])
if test $GCOV = ":"; then
  AC_MSG_WARN([Unable to detect gcov in your path. You will not be able \
  to generate nfhcctl tests coverage.], 2)
  gcov="no";
else
  gcov="yes";
fi

#======== Checking valgrind
AC_CHECK_PROG([VALGRIND], [valgrind], [yes], [no])
if test $VALGRIND = ":"; then
  AC_MSG_WARN([Unable to detect valgrind in your path. You will not be able \
  to generate dynamic memory usage in nfhcctl tests.], 2)
  valgrind="no";
else
  valgrind="yes";
fi

#############################################################################
## Supplementary options
#############################################################################
#======== debug chars
AC_ARG_WITH(debug, [  --with-debug            Activate -g option of gcc and delete -DNDEBUG macro])
if test "$with_debug" = "yes"
then
	debug="yes";
        DEBUG="-ggdb";
else
	debug="no";
        DEBUG="";
fi

CFLAGS="$CFLAGS \
 -std=c99 -O2 -Wall -Wextra -W -Werror -Wtrigraphs -Wundef -Wswitch -Wunused \
 -Wimplicit -fno-common -Wcast-qual -Wcast-align -Wwrite-strings \
 -Wuninitialized -Winit-self -Wmissing-prototypes -Wpacked -Wnested-externs \
 -Waggregate-return -pedantic -Wshadow -O3 \
 $DEBUG -D_XOPEN_SOURCE=600 -std=c99";

#############################################################################
## Environment variables activation
#############################################################################

AM_CONDITIONAL(EFENCE, test x$efence = xyes)
AM_CONDITIONAL(GCOV, test x$gcov = xyes)
AM_CONDITIONAL(GPROF, test x$gprof = xyes)

case "$host" in
    (*-*-linux*|*-*-openbsd*)
	PAM_MODDIR='${slibdir}/security'
	;;
    (*-*-solaris*|*-*-netbsd*)
	PAM_MODDIR='${libdir}/security';
	;;
    (*-*-darwin*)
	PAM_MODDIR='${libdir}/pam';
	;;
    (*)
	PAM_MODDIR='${libdir}';
	;;
esac
AC_SUBST([PAM_MODDIR])

#############################################################################
## Makefile list and finish
#############################################################################

AC_CONFIG_FILES([
Makefile
doc/Makefile
src/Makefile
])

AC_OUTPUT

echo;
echo Configuration completed;
echo;
echo System detected................... `uname -s`;
echo Doxygen found..................... $doxygen;
echo valgrind found.................... $valgrind;
echo Libefence enabled................. $efence;
echo Gprof activated................... $gprof;
echo Gcov activated.................... $gcov;
echo;
echo Type make to compile;
echo;

