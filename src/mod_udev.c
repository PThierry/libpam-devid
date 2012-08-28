/*
** pam_mod_udev.c for libpam_devid in libpam-devid/src
**
** Made by Philippe THIERRY
** Login   <Philippe.thierry@thalesgroup.com>
**
** Started on  mar. 28 août 2012 15:46:08 CEST Philippe THIERRY
*/

#include "pam_mod_api.h"

int __push_device(pam_handle_t *pamh __attribute__((unused)),
                  const char *name __attribute__((unused)),
                  const char*device __attribute__((unused)))
{
  return 0;
}

void __clean_policy(pam_handle_t *pamh __attribute__((unused)),
                    const char *name __attribute__((unused)))
{
  /* open daemon socket */
  /* request for policy clean for given user */
  /* close policy */
}
