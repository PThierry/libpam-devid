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
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
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
  bool pam_conf;
  int  min_uid;
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

/* FIXME: before getting from pam env, to be replaced by config file */
union u_foo {
  const char **const_attr;
  char **attr;
};

/* pam args structure for argument management */
struct pam_args pam_args;

/* module configuration structure, loaded from file given in mod arg or in /etc/pam_devid.conf if not given */
/*!
 ** @brief  the PAM devid module configuration structure
 */
struct pam_devid_conf {
  char *ldap_uri; /**< the LDAP server URI */
  char *ldap_root_dn; /**< the LDAP server root dn */
  char *ldap_base_dn; /**< The LDAP server base dn */
  char *ldap_root_pw; /**< the LDAP root passwd */
};

/*
** By now the devid conf structure is a global variable, loaded at open_session() call.
** The module as NO MEMORY from a call to another by now. Set to NULL when
** loaded.
*/
struct pam_devid_conf devid_conf = {
  NULL, NULL, NULL, NULL
};


/*!
 ** @brief load_configuration load the module configuration from module's config file
 **
 ** FIXME: loading the config file should be done here
 ** 
 ** @param file the file full path 
 */
static void load_configuration(pam_handle_t *pamh,
                               const char *file)
{
  int fd;
  fd = open(file, O_RDONLY);
  if (fd != -1) {
    if (pam_args.pam_debug == true) {
      pam_syslog(pamh, LOG_INFO, "Opened config file %s", file);
    }

  } else {
    pam_syslog(pamh, LOG_ERR, "Unable to open pam_devid config file!");
  }
}

/*!
 ** @brief request_devid_from_ldap gets the list of devid in the LDAP database
 **
 ** All these devid are serialid stored in the LDAP database and are used to
 ** set them in the local device firewall as a whitelist. Any preexisting list
 ** is cleaned (one user devids at a time in the whitelist by now)
 ** 
 ** @param pamh PAM module handler
 ** @param argc the module's argc
 ** @param argv the module's argv
 ** 
 ** @return  always 0 by now
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
  /* count the number of returned entry (should be one - the user data)*/
  if (ldap_count_entries(ld, msg) == 0) {
    pam_syslog(pamh, LOG_ERR, "no entry found!");
  } else {
    LDAPMessage *entry = NULL;
    entry = ldap_first_entry(ld, msg);
    /* get the entry content */
    if (entry) {
      struct berval **entryval;
      entryval = ldap_get_values_len(ld, entry, "uidNumber");
      if (entryval) {
        pam_syslog(pamh, LOG_INFO, "uid found for user %s: %s", name, entryval[0]->bv_val);
        if (strtol(entryval[0]->bv_val, NULL, 10) < pam_args.min_uid) {
          if (pam_args.pam_debug == true) {
            pam_syslog(pamh, LOG_INFO, "uid (%s) smaller than minimum requested (%d)", entryval[0]->bv_val, pam_args.min_uid);
          }
          free(ldap_filter);
          return 0;
        }
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
 ** @brief parse_pam_args parse the pam module arguments
 **
 ** List of arguments:
 ** - enable_pam_user: future use
 ** - debug: enable full debug. If not present, no debug printed in auth.log
 ** - config: set the config file (config=/path/to/config). If not set, config file /etc/pam_devid.conf is used)
 ** - min_uid: set the minimum uid for each we have to get back the list of devid (mmin_uid=NUM). Default: 999. 
 **
 ** @param pamh the PAM module handler, for pam_syslog
 ** @param argc the module argc
 ** @param argv the module argv
 */
static void parse_pam_args(pam_handle_t *pamh, int argc, const char **argv)
{
  int i;

  assert(argc >= 0);
  for (i = 0; i < argc; i++)
    assert(argv[i] != NULL);

  /* first, set default values */
  pam_args.get_uid_from_pam    = true;
  pam_args.pam_debug           = false;
  pam_args.pam_conf            = false;
  pam_args.min_uid	       = 999;

  for (i = 0; i < argc; ++i) {
    if (strcasecmp("enable_pam_user", argv[i]) == 0)
      pam_args.get_uid_from_pam = true;
    else if (strcasecmp("debug", argv[i]) == 0)
      pam_args.pam_debug = true;
    /* get conf file ... */
    if (strncmp("config=", argv[i], 7) == 0 && strlen(argv[i]) > 7) {
      load_configuration(pamh, &(argv[i][7])); /* ... and load */
      pam_args.pam_conf = true;
    } else {
      pam_syslog(pamh, LOG_ERR, "unknown pam_devid option \"%s\"\n", argv[i]);
    }
    /* get min uid */
    if (strncmp("min_uid=", argv[i], 8) == 0 && strlen(argv[i]) > 8) {
      pam_args.min_uid = strtol(&(argv[i][8]), NULL, 10);
    } else {
      pam_syslog(pamh, LOG_ERR, "unknown pam_devid option \"%s\"\n", argv[i]);
    }
  }
  if (pam_args.pam_conf == false) {
    load_configuration(pamh, "/etc/pam_devid.conf"); /* ... and load */
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
 ** @return always 0 for the moment
 */
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh,
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
 ** @return always 0 for the moment
 */
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh,
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

