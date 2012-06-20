/*
** libpam_devid.c for libpam-devid in /home/phil/Travail/Development/Pam/libpam-devid/src
**
** Made by Philippe THIERRY
** Login   <Philippe THIERRY@reseau-libre.net>
**
** Started on  mer. 20 juin 2012 15:24:10 CEST Philippe THIERRY
*/

#define PAM_SM_SESSION 1

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <syslog.h>
#include <assert.h>
#include <strings.h>
#include <stdbool.h>
#include <stdlib.h>

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh,
                                   int          flags,
                                   int          argc,
                                   const char** argv);

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh,
                                    int		 flags,
                                    int          argc,
                                    const char** argv);

struct pam_args {
  bool get_uid_from_pam;
  bool pam_debug;
};

/* pam args structure for argument management */
struct pam_args pam_args;

/*!
 ** @brief parse_pam_args
 ** 
 ** @param argc 
 ** @param argv 
 */
static void parse_pam_args(pam_handle_t *pamh, int argc, const char **argv)
{
  int i;

  assert(argc >= 0);
  for (i = 0; i < argc; i++)
    assert(argv[i] != NULL);

  /* first, set default values */
  pam_args.get_uid_from_pam    = true;

  for (i = 0; i < argc; ++i) {
    if (strcasecmp("enable_pam_user", argv[i]) == 0)
      pam_args.get_uid_from_pam = true;
    else if (strcasecmp("debug", argv[i]) == 0)
      pam_args.pam_debug = true;
    else
      pam_syslog(pamh, LOG_ERR, "unknown pam_devid option \"%s\"\n", argv[i]);
  }
}

/*!
 ** @brief pam_sm_open_session is called when a user session is opened
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
  int ret __attribute__((unused));
  char *name;
  parse_pam_args(pamh, argc, argv);
  ret = pam_get_item(pamh, PAM_USER,  (const void **)&name);
  pam_syslog(pamh, LOG_ERR, "foo");
  return 0;
}

/*!
 ** @brief pam_sm_close_session is called when a user session is closed
 ** 
 ** @param __attribute__((unused ))
 ** @param  
 ** 
 ** @return 
 */
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh __attribute__((unused)),
                                   int          flags __attribute__((unused)),
                                   int          argc __attribute__((unused)),
                                   const char** argv __attribute__((unused)))
{
  return 0;
}

