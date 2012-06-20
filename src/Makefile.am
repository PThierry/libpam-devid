##
## Makefile.am for libpam-devid in /home/phil/Travail/Development/Pam/libpam-devid/src
##
## Made by Philippe THIERRY
## Login   <Philippe THIERRY@reseau-libre.net>
##
## Started on  mer. 20 juin 2012 15:30:31 CEST Philippe THIERRY
## Last update mer. 20 juin 2012 15:30:31 CEST Philippe THIERRY
##

SUBDIRS = .

varrundir = ${localstatedir}/run

moduledir = @PAM_MODDIR@
module_LTLIBRARIES = pam_devid.la

pam_devid_la_SOURCES = pam_devid.c
pam_devid_la_CFLAGS = ${AM_CFLAGS}
pam_devid_la_LDFLAGS = -module -avoid-version


AM_CFLAGS = -I$(top_srcdir)/src/lib/utils -I$(top_srcdir)/src/lib/string -I$(top_srcdir)/src/lib/list -I$(top_srcdir)/src/lib/memtrace -I$(top_srcdir)/src/lib/debug $(CFLAGS)

pam_devid_la_SOURCES = main.c

# options part
if EFENCE
pam_devid_LDADD += $(EFENCEFLAGS)
endif
#

EXTRA_DIST = 

CLEANFILES = *~ .*.swp .*.swo output* *.gcov *.gprof

