/*
** libpam_devid.c for libpam-devid in /home/phil/Travail/Development/Pam/libpam-devid/src
**
** Made by Philippe THIERRY
** Login   <Philippe THIERRY@reseau-libre.net>
**
** Started on  mer. 20 juin 2012 15:24:10 CEST Philippe THIERRY
*/

#define PAM_SM_SESSION

#include <security/pam_modules.h>

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh,
                                   int          flags,
                                   int          argc,
                                   const char** argv);



/*!
 ** @brief pam_sm_open_session
 ** 
 ** @param pamh 
 ** @param flags 
 ** @param argc 
 ** @param argv 
 ** 
 ** @return 
 */
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh __attribute__((unused)),
                                   int          flags __attribute__((unused)),
                                   int          argc __attribute__((unused)),
                                   const char** argv __attribute__((unused)))
{
  return 0;
}
