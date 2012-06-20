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
#include <stdio.h>
#include <stdarg.h>
/* for ldap */
#include <ldap.h>

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

/* ldap part. Needed for LDAP server configuration, to be supported through configuration */
LDAP *ld;
#define LDAP_PORT 389
int  auth_method    = LDAP_AUTH_SIMPLE;
int  desired_version = LDAP_VERSION3;
const char * const ldap_uri     = "ldap://vm-ldap:389/";
const char * const root_dn       = "cn=admin,dc=testbed,dc=local";
const char * const base_dn       = "ou=People,dc=testbed,dc=local";
struct berval creds;
const char *ldap_attributes[] = {
  "cn",
  "uid",
  "uidNumber",
  NULL
};

/* FIXME: before getting from pam env */
union u_foo {
  const char **const_attr;
  char **attr;
};

/* pam args structure for argument management */
struct pam_args pam_args;

/*!
 ** @brief request_devid_from_ldap
 ** 
 ** @param pamh 
 ** @param argc
 ** @param argv
 ** 
 ** @return 0
 */
static int request_devid_from_ldap(pam_handle_t *pamh,
                                   char *name,
                                   int argc __attribute__((unused)),
                                   const char **argv __attribute__((unused)))
{
  creds.bv_len = 10;
  creds.bv_val = strdup("xxxxxxxxxx");
  LDAPMessage *msg = NULL;
  union u_foo foo;
  char *ldap_filter = NULL;

  ldap_filter = malloc(128);
  snprintf(ldap_filter, 127, "(uid=%s)", name);
  /* FIXME: to be replaced by a proper conf */
  foo.const_attr = ldap_attributes;

  int  res;
  /* initialize the ldap library */
  if ((res = ldap_initialize(&ld, ldap_uri)) != 0) {
    if (pam_args.pam_debug == true) {
      pam_syslog(pamh, LOG_ERR, "ldap_init failed");
    }
    free(ldap_filter);
    return 1;
  }
  /* set ldap option (protocol version) */
  if (ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &desired_version) != LDAP_OPT_SUCCESS)
  {
    if (pam_args.pam_debug) {
      pam_syslog(pamh, LOG_ERR, "ldap_set_option failed!");
    }
    free(ldap_filter);
    return 1;
  }
  /* binding to LDAP server */
  if (ldap_sasl_bind_s(ld, root_dn,
                       NULL, /* SIMPLE authentication (no SASL) */
                       &creds,
                       NULL, NULL, NULL) /* No SSL */
                       != LDAP_SUCCESS ) {
    if (pam_args.pam_debug) {
      pam_syslog(pamh, LOG_ERR, "ldap_bind failed!");
    }
    free(ldap_filter);
    return 1;
  }
  /* Let's search for user, and get uid and devid */
  res = ldap_search_ext_s(ld,
                          base_dn,
                          LDAP_SCOPE_SUB,
                          ldap_filter, /* filter: const char* */
                          foo.attr,
                          0,
                          NULL, /* no specified timeout */
                          NULL, NULL, /* no SSL */
                          12 /* max entries*/,
                          &msg);
  if (ldap_count_entries(ld, msg) == 0) {
    pam_syslog(pamh, LOG_ERR, "no entry found!");
  } else {
    LDAPMessage *entry = NULL;
    entry = ldap_first_entry(ld, msg);
    if (entry) {
      struct berval **entryval;
      entryval = ldap_get_values_len(ld, entry, "uidNumber");
      if (entryval) {
        pam_syslog(pamh, LOG_ERR, "uid found for user %s: %s", name, entryval[0]->bv_val);
      }
    } else {
      pam_syslog(pamh, LOG_ERR, "entry is NULL!");
    }
  }
  ldap_msgfree(msg);
  /* unbind from LDAP server */
  res = ldap_unbind_ext(ld, NULL, NULL);
  if (res != 0) {
    pam_syslog(pamh, LOG_ERR, "ldap_unbind_s: %s", ldap_err2string(res));
    free(ldap_filter);
    return 1;
  }
  pam_syslog(pamh, LOG_ERR, "request from LDAP done");
  free(ldap_filter);
  return 0;
}

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
  pam_args.pam_debug               = false;

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
 ** @param pamh the current pam module handler, given by PAM 
 ** @param flags the PAM flags (NULL or PAM_SILENT)
 ** @param argc the module's arguments list counter 
 ** @param argv the module's arguments list
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
  if (ret != PAM_SUCCESS) {
    pam_syslog(pamh, LOG_ERR, "error when getting PAM_USER item !");
  }
  if (name && pam_args.pam_debug) {
    pam_syslog(pamh, LOG_INFO, "user %s session opened", name);
  }
  request_devid_from_ldap(pamh, name, argc, argv);
  return 0;
}

/*!
 ** @brief pam_sm_close_session is called when a user session is closed
 ** 
 ** @param pamh the current pam module handler, given by PAM 
 ** @param flags the PAM flags (NULL or PAM_SILENT)
 ** @param argc the module's arguments list counter 
 ** @param argv the module's arguments list
 ** 
 ** @return 0
 */
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh __attribute__((unused)),
                                   int          flags __attribute__((unused)),
                                   int          argc __attribute__((unused)),
                                   const char** argv __attribute__((unused)))
{
  char *name;
  int ret __attribute__((unused));

  ret = pam_get_item(pamh, PAM_USER,  (const void **)&name);
  if (name && pam_args.pam_debug) {
    pam_syslog(pamh, LOG_INFO, "user %s session closed", name);
  }
  return 0;
}

