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
#noinst_HEADERS = pam_mod_api.h

module_LTLIBRARIES = pam_devid.la

pam_devid_la_SOURCES = pam_devid.c
EXTRA_pam_devid_la_SOURCES = mod_udev.c mod_sample.c
pam_devid_la_CFLAGS = ${AM_CFLAGS} -fPIC
pam_devid_la_LDFLAGS = -module -avoid-version
pam_devid_la_DEPENDENCIES = $(PAM_DEVID_MOD)
pam_devid_la_LIBADD = $(PAM_DEVID_MOD) -lldap

# options part
if EFENCE
pam_devid_la_LIBADD += $(EFENCEFLAGS)
endif
#
EXTRA_DIST = 

CLEANFILES = *~ .*.swp .*.swo output* *.gcov *.gprof

