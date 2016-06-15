/*
** pam_mod_udev.h for libpam-devid in libpam-devid/src
**
** Made by Philippe THIERRY
** Login   <Philippe.thierry@reseau-libre.net>
**
** Started on  mar. 28 août 2012 15:46:39 CEST Philippe THIERRY
*/

/*
** This file implement the udev based hotplug device filtering.
**
** Using this module, the libpam-devid interact with a deamon listening
** for udev events. policy updates are pushed to the daemon by this module
** and the daemon manage the newly plugged in devices depending on the policy
** given.
*/

#ifndef PAM_MOD_UDEV_H_
# define PAM_MOD_UDEV_H_

#include <security/pam_modules.h>
#include <security/pam_ext.h>

int __init_module(void);

int __push_device(pam_handle_t *pamh, const char *name, const char*device);

void __clean_policy(pam_handle_t *pamh, const char *name);

int __release_module(void);

#endif /* !PAM_MOD_UDEV_H_ */
