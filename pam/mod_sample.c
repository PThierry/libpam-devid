/*
** mod_sample.c for pam_devid in libpam-devid/pam
**
** Made by Philippe THIERRY
** Login   <Philippe.THIERRY@thalesgroup.com>
**
** Started on  mer. 29 août 2012 10:54:11 CEST Philippe THIERRY
*/

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <syslog.h>

#include "pam_mod_api.h"

#define MODULENAME "pam_devid_sample"

int __init_module(void)
{
  return 0;
}

int __push_device(pam_handle_t *pamh,
                  const char *name,
                  const char*device)
{
  pam_syslog(pamh, LOG_INFO, "receiving device %s (user %s) to be pushed", device, name);
  return 0;
}

void __clean_policy(pam_handle_t *pamh,
                    const char *name)
{
  if (name) {
    pam_syslog(pamh, LOG_INFO, "ask for policy clean for user %s", name);
  } else {
    pam_syslog(pamh, LOG_INFO, "ask for complete policy clean");
  }
}

int __release_module(void)
{
  return 0;
}
