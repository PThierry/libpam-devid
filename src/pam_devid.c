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

/* ldap part. Needed for LDAP server configuration, to be supported through configuration */
#define LDAP_PORT 389
int  auth_method    = LDAP_AUTH_SIMPLE;
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


/* module configuration structure, loaded from file given in mod arg or in /etc/pam_devid.conf if not given */
/*!
 ** @brief  the PAM devid module configuration structure
 **
 ** This structure is dynamically set and unset when sessions are opened/closed
 */
struct pam_devid_conf {
  char *ldap_uri; /**< the LDAP server URI */
  char *ldap_bind_dn; /**< the LDAP server root dn */
  char *ldap_bind_pw; /**< the LDAP root passwd */
  char *ldap_base_dn; /**< The LDAP server base dn */
  int  ldap_scope; /* LDAP search scope (one, base or sub)*/
  int  ldap_timelimit; /**< LDAP requests timeout value */
  int  ldap_version; /**< LDAP protocol version to use (2 or 3) */
  bool ldap_tls_checkpeer; /**< LDAP Certificate authentication ? */
  char *ldap_tls_cacertfile; /**< CA Certificate file for TLS */
  char *ldap_tls_cacertdir; /**< TLS Certificate directory */
  char *ldap_tls_ciphers; /**< Supported ciphers list for TLS */
  char *ldap_tls_cert; /**< Certificate file for TLS */
  char *ldap_tls_key; /**< TLS key for TLS session init */
  bool ldap_ssl; /**< use SSL for LDAP ? */
  bool ldap_tls; /**< use TLS for LDAP ? */
  char *ldap_sasl_mechanism; /**< which SASL mechanism is used. By now only SIMPLE */
  char *ldap_login_attr; /**< LDAP attribute for login name (for search) */
  bool pam_debug; /**< activate debug mode for module ? */
  char *pam_conf_file; /**< config file to set this very structure */
  bool pam_conf_loaded; /**< set to true when this structure is completely loaded */
  uid_t pam_min_uid; /**< minimum uid for requesting devid in LDAP */
  uid_t pam_max_uid; /**< maximum uid for requesting devid in LDAP */
};

typedef struct pam_devid_conf pam_devid_config_t;

/* pam args structure for argument management */
pam_devid_config_t pam_args;

/*
** By now the devid conf structure is a global variable, loaded at open_session() call.
** The module as NO MEMORY from a call to another by now. Set to NULL when
** loaded.
*/

/*!
** @brief Buffer length for per-line configuration file parsing.
** We consider 256 enough for any line. If the line is longer, its value is
** truncated to this size.
*/
#define BUFSIZE 128

/*!
 ** @brief clean_configuration clean the configuration structure
 **
 ** the configuration structure is set each time a new section is started and
 ** an existing session is closed. As a consequence, the structure needs to be
 ** properly cleaned each time in order to avoid memory leak
 */
static
void clean_configuration(void)
{
  if (pam_args.ldap_uri != NULL) {
    free(pam_args.ldap_uri);
  }
  if (pam_args.ldap_bind_dn != NULL) {
    free(pam_args.ldap_bind_dn);
  }
  if (pam_args.ldap_bind_pw != NULL) {
    free(pam_args.ldap_bind_pw);
  }
  if (pam_args.ldap_base_dn != NULL) {
    free(pam_args.ldap_base_dn);
  }
  if (pam_args.ldap_tls_cacertfile != NULL) {
    free(pam_args.ldap_tls_cacertfile);
  }
  if (pam_args.ldap_tls_cacertdir != NULL) {
    free(pam_args.ldap_tls_cacertdir);
  }
  if (pam_args.ldap_tls_ciphers != NULL) {
    free(pam_args.ldap_tls_ciphers);
  }
  if (pam_args.ldap_tls_cert != NULL) {
    free(pam_args.ldap_tls_cert);
  }
  if (pam_args.ldap_tls_key != NULL) {
    free(pam_args.ldap_tls_key);
  }
  if (pam_args.ldap_sasl_mechanism != NULL) {
    free(pam_args.ldap_sasl_mechanism);
  }
  if (pam_args.ldap_login_attr != NULL) {
    free(pam_args.ldap_login_attr);
  }
  if (pam_args.pam_conf_file != NULL) {
    free(pam_args.pam_conf_file);
  }
}

/*!
 ** @brief load_configuration load the module configuration from module's config file
 **
 ** FIXME: loading the config file should be done here
 **
 ** CAUTION: The code of this function is based on a GPL function not written by me (libpam-ldap
 ** code for config file parsing) Should be replaced by another one in order
 ** to maintain a Thales proprietary license
 **
 ** @param pamh pam module handler for logging
 ** @param file the file full path 
 ** @param config the config structure pointer
 */
static int load_configuration(pam_handle_t *pamh,
                              const char *file,
                              pam_devid_config_t *config)
{
  /* this is the same configuration file as nss_ldap */
  FILE *fp;
  char b[BUFSIZE];

  /* set structure attributes to NULL/0/false */
  memset(config, 0, sizeof(pam_devid_config_t));
  fp = fopen(file, "r");
  config->pam_min_uid = 999;

  if (fp == NULL)
  {
    if (pam_args.pam_debug == true) {
      pam_syslog(pamh, LOG_INFO, "Opened config file %s", file);
    }
    /*
     * According to PAM Documentation, such an error in a config file
     * SHOULD be logged at LOG_ALERT level
     */
    syslog (LOG_ALERT, "pam_ldap: missing file \"%s\"", file);
    return PAM_SERVICE_ERR;
  }

  config->ldap_scope = LDAP_SCOPE_SUBTREE;

  while (fgets (b, sizeof (b), fp) != NULL)
  {
    char *k, *v;
    int len;

    /* empty and commented lines */
    if (*b == '\n' || *b == '#')
      continue;

    k = b;
    v = k;
    /* push line offset pointer to next space/tab */
    while (*v != '\0' && *v != ' ' && *v != '\t')
      v++;

    if (*v == '\0')
      continue; /* no value */

    /* then on a space, ending previous substring so that the value name is ended properly */
    *(v++) = '\0';

    /* skip all whitespaces between keyword and value */
    /* Lars Oergel <lars.oergel@innominate.de>, 05.10.2000 */
    while (*v == ' ' || *v == '\t')
      v++;

    /* kick off all whitespaces and newline at the end of value */
    /* Bob Guo <bob@mail.ied.ac.cn>, 08.10.2001 */
    len = strlen (v) - 1;
    while (v[len] == ' ' || v[len] == '\t' || v[len] == '\n')
      --len;
    v[len + 1] = '\0';

    /*
    ** okay now we have to string pointer: k, the value name, v the value
    ** content.
    */
    if (!strcasecmp(k, "uri")) {
      config->ldap_uri = strdup(v);
    }
    else if (!strcasecmp(k, "basedn")) {
      config->ldap_base_dn = strdup(v);
    }
    else if (!strcasecmp(k, "binddn")) {
      config->ldap_bind_dn = strdup (v);
    }
    else if (!strcasecmp(k, "bindpw")) {
      config->ldap_bind_pw = strdup(v);
    }
    else if (!strcasecmp (k, "scope")) {
      if (!strncasecmp (v, "sub", 3))
        config->ldap_scope = LDAP_SCOPE_SUBTREE;
      else if (!strncasecmp(v, "one", 3))
        config->ldap_scope = LDAP_SCOPE_ONELEVEL;
      else if (!strncasecmp(v, "base", 4))
        config->ldap_scope = LDAP_SCOPE_BASE;
    }
    else if (!strcasecmp (k, "timelimit")) {
      config->ldap_timelimit = atoi (v);
    }
    else if (!strcasecmp (k, "ldap_version")) {
      config->ldap_version = atoi(v);
    }
    else if (!strcasecmp (k, "ssl")) {
      if (!strcasecmp (v, "on") || !strcasecmp (v, "yes") || !strcasecmp (v, "true")) {
        config->ldap_ssl = true;
      }
      else if (!strcasecmp (v, "start_tls")) {
        config->ldap_tls = true;
      }
    }
    else if (!strcasecmp (k, "pam_min_uid")) {
      config->pam_min_uid = (uid_t)atol(v);
    }
    else if (!strcasecmp (k, "pam_max_uid")) {
      config->pam_max_uid = (uid_t)atol(v);
    }
    /* future use: authentify LDAP server */
    else if (!strcasecmp (k, "tls_checkpeer")) {
      if (!strcasecmp (v, "on") || !strcasecmp (v, "yes") || !strcasecmp (v, "true")) {
        config->ldap_tls_checkpeer = true;	/* LDAP_OPT_X_TLS_HARD */
      }
      else if (!strcasecmp (v, "off") || !strcasecmp (v, "no") || !strcasecmp (v, "false")) {
        config->ldap_tls_checkpeer = false;	/* LDAP_OPT_X_TLS_NEVER */
      }
    }
    else if (!strcasecmp(k, "tls_cacertfile")) {
      config->ldap_tls_cacertfile = strdup(v);
    }
    else if (!strcasecmp(k, "tls_cacertdir")) {
      config->ldap_tls_cacertdir = strdup (v);
    }
    else if (!strcasecmp (k, "tls_ciphers")) {
      config->ldap_tls_ciphers = strdup (v);
    }
    else if (!strcasecmp (k, "tls_cert")) {
      config->ldap_tls_cert = strdup (v);
    }
    else if (!strcasecmp (k, "tls_key")) {
      config->ldap_tls_key = strdup (v);
    }
    /* end of SSL/TLS specific options */
    else if (!strcasecmp (k, "pam_sasl_mech")) {
      if (!strcasecmp(v, "simple")) {
        config->ldap_sasl_mechanism = strdup(v);
      } else {
        pam_syslog(pamh, LOG_WARNING, "Only SIMPLE SASL mechanism supported!");
      }
    }
    else if (!strcasecmp (k, "debug")) {
      if (!strcasecmp (v, "on") || !strcasecmp (v, "yes") || !strcasecmp (v, "true"))
        config->pam_debug = true;
      else
        config->pam_debug = false;
    }
  } /* end of while() */
  /* okay no check that all necessary configuration data is set */
  if (config->ldap_uri == NULL) {
    syslog (LOG_ALERT, "pam_devid: missing LDAP URI in file \"%s\"", file);
    return PAM_SERVICE_ERR;
  }
  if (config->ldap_bind_dn == NULL) {
    syslog (LOG_ALERT, "pam_devid: missing LDAP bind DN in file \"%s\"", file);
    return PAM_SERVICE_ERR;
  }
  if (config->ldap_bind_pw == NULL) {
    syslog (LOG_ALERT, "pam_devid: missing LDAP bind password in file \"%s\"", file);
    return PAM_SERVICE_ERR;
  }
  if (config->ldap_base_dn == NULL) {
    syslog (LOG_ALERT, "pam_devid: missing LDAP nase DN in file \"%s\"", file);
    return PAM_SERVICE_ERR;
  }
  /* and set default values if not setted */
  if (config->ldap_login_attr == NULL) {
    config->ldap_login_attr = strdup("uid");
  }
  fclose (fp);

  memset (b, 0, BUFSIZE);
  config->pam_conf_loaded = true;
  return PAM_SUCCESS;
}

/*!
 ** @brief request_devid_from_ldap gets the list of devid in the LDAP database
 **
 ** All these devid are serialid stored in the LDAP database and are used to
 ** set them in the local device firewall as a whitelist. Any preexisting list
 ** is cleaned (one user devids at a time in the whitelist by now)
 ** 
 ** @param pamh PAM module handler
 ** @param name the user name used for LDAP search
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
  LDAP *ld;
  struct berval creds;
  creds.bv_val = pam_args.ldap_bind_pw;
  creds.bv_len = strlen(pam_args.ldap_bind_pw); /* Not NULL, checked during config load */
  LDAPMessage *msg = NULL;
  union u_foo foo;
  char *ldap_filter = NULL;
  int  res;

  ldap_filter = malloc(128);
  snprintf(ldap_filter, 127, "(%s=%s)", pam_args.ldap_login_attr, name);
  /* FIXME: to be replaced by a proper conf */
  foo.const_attr = ldap_attributes;

  /* initialize the ldap library */
  if ((res = ldap_initialize(&ld, pam_args.ldap_uri)) != 0) {
    if (pam_args.pam_debug == true) {
      pam_syslog(pamh, LOG_ERR, "ldap_init failed");
    }
    free(ldap_filter);
    return 1;
  }
  /* set ldap option (protocol version) */
  if (ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &(pam_args.ldap_version)) != LDAP_OPT_SUCCESS)
  {
    if (pam_args.pam_debug) {
      pam_syslog(pamh, LOG_ERR, "ldap_set_option failed!");
    }
    free(ldap_filter);
    return 1;
  }
  /* binding to LDAP server */
  if (ldap_sasl_bind_s(ld, pam_args.ldap_bind_dn,
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
                          pam_args.ldap_base_dn,
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
        if (strtol(entryval[0]->bv_val, NULL, 10) < pam_args.pam_min_uid) {
          if (pam_args.pam_debug == true) {
            pam_syslog(pamh, LOG_INFO, "uid (%s) smaller than minimum requested (%d)", entryval[0]->bv_val, pam_args.pam_min_uid);
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
 **
 ** @return PAM_SUCCESS if correctly done, of PAM_FAILED if not properly treated
 */
static
int load_all_options(pam_handle_t *pamh, int argc, const char **argv)
{
  int i;
  int ret = PAM_SERVICE_ERR;

  assert(argc >= 0);
  for (i = 0; i < argc; i++)
    assert(argv[i] != NULL);

  /* first, set default values */
  pam_args.pam_debug           = false;
  pam_args.ldap_version        = 3;
  pam_args.pam_conf_loaded     = false;

  for (i = 0; i < argc; ++i) {
    if (strcasecmp("debug", argv[i]) == 0) {
      pam_args.pam_debug = true;
    }
    else if (strncmp("config=", argv[i], 7) == 0 && strlen(argv[i]) > 7) {
      /* get conf file ... */
      ret = load_configuration(pamh, &(argv[i][7]), &pam_args); /* ... and load */
    } else {
      pam_syslog(pamh, LOG_ERR, "unknown pam_devid option \"%s\"\n", argv[i]);
    }
  }
  if (pam_args.pam_conf_loaded == false) {
    ret = load_configuration(pamh, "/etc/pam_devid.conf", &pam_args); /* ... and load from std file if no file given in arg */
  }
  return ret;
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
                                   int          argc,
                                   const char** argv)
{
  char *name;
  int devid_res = PAM_SERVICE_ERR;

  devid_res = load_all_options(pamh, argc, argv);
  if (devid_res == PAM_SUCCESS) {
    devid_res = pam_get_item(pamh, PAM_USER,  (const void **)&name);
    if (devid_res != PAM_SUCCESS) {
      pam_syslog(pamh, LOG_ERR, "error when getting PAM_USER item !");
    }
    if (name && pam_args.pam_debug) {
      pam_syslog(pamh, LOG_INFO, "user %s session opened", name);
    }
    request_devid_from_ldap(pamh, name, argc, argv);
  } else {
    pam_syslog(pamh, LOG_ERR, "error during configuration, leaving.");
  }
  clean_configuration();
  return devid_res;
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
  int devid_res = PAM_SERVICE_ERR;

  pam_get_item(pamh, PAM_USER,  (const void **)&name);
  if (name && pam_args.pam_debug) {
    pam_syslog(pamh, LOG_INFO, "user %s session closed", name);
  }
  /*
  ** Okay nothing is done here. We need to manage session counter in order to
  ** update local key list only if a _new_ user is logging in, not a
  ** previously logged in anther call.
  ** As a consequence, we need to count the number of session open/close
  ** in order to know if wee have to load a new keylist or not.
  */
  devid_res = PAM_SUCCESS;
  return devid_res;
}

