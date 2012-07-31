/*
** libpam_devid.c for libpam-devid in /home/phil/Travail/Development/Pam/libpam-devid/src
**
** Made by Philippe THIERRY
** Login   <Philippe THIERRY@reseau-libre.net>
**
** Started on  mer. 20 juin 2012 15:24:10 CEST Philippe THIERRY
*/

#define PAM_SM_SESSION 1

#include <syslog.h>
#include <assert.h>
#include <strings.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <inttypes.h>
#include <utmp.h>


int getutmp(int *fd, struct utmp *utmp)
{
	if (*fd < 0)
		*fd = open(_PATH_UTMP, O_RDONLY);
	if (read(*fd, utmp, sizeof(*utmp)) == sizeof(*utmp))
		return 1;
	close(*fd);
	return 0;
}


int main(int argc, char** argv)
{
  char *name = NULL;
  int ctx_res;
  const void *data;
  struct pam_module_ctx *module_ctx = NULL;
  struct utmp utmp;
  struct password *pw = NULL;
  int fd = -1;

  fd = open("/var/run/utmp", O_RDONLY, 0);
  /* check if the user is already logged in using utmp. If logged in, then just leave */
  while (read(fd, (char*)&utmp, sizeof(struct utmp)) == sizeof(struct utmp)) {
    if (utmp.ut_type == DEAD_PROCESS) {
      printf("[DEAD] user %s was logged in, on tty %s from host %s\n", utmp.ut_name, utmp.ut_line, utmp.ut_host);
    } else if (utmp.ut_type == USER_PROCESS) {
      printf("[USER] user %s is logged in, on tty %s from host %s\n", utmp.ut_name, utmp.ut_line, utmp.ut_host);
    } else {
      printf("[OTHER] service %s already logged in, on tty %s from host %s\n", utmp.ut_name, utmp.ut_line, utmp.ut_host);
      /* if tty is a local one, leave */
    }
  }
  close(fd);
  return 0;
}
