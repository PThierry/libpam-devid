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
#include <inttypes.h>
#include <unistd.h>
/* for ldap */
#include <ldap.h>
/* for utmp */
#include <utmp.h>

#include "pam_mod_api.h"

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

/** @brief user management tristate value. Specify how multi-user local logins should be managed */
enum user_tristate
{
  USER_FIRST_LOGGED = 1, /**< the first local user logged in get the policy. No other policy is added while at least one local user exists */
  USER_MERGE, /**< merge any new local user policy to the existing one. All local users have their device(s) allowed */
  USER_LAST_LOGGED, /**< Each time a new user log in localy, the policy is set to support his devices exclusively */
  USER_MAX /**< First invalid value */
};

typedef enum user_tristate user_tristate_t;



#define MODNAME "pam-devid"

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
  user_tristate_t pam_user_mgmt; /**< set to True if local user concurrency is disabled */
};

typedef struct pam_devid_conf pam_devid_config_t;

/*
** Context state for a given uid. Specify the session refcount (number of
** opened session minus number of closed session) While refcount is positive,
** the session is still logged on the system. Permits to manage multiple
** simultaneous login/xdm connections.
*/
struct context_state {
  uint32_t	uid;
  uint32_t	refcount;
};

/* context vector for all currently logged users */
typedef struct context_state ctx_state_t;

struct pam_module_ctx {
  ctx_state_t *ctx_vector;
  pam_devid_config_t config;
};


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
void clean_configuration(struct pam_module_ctx *ctx)
{
  if (ctx == NULL) {
    return;
  }
  /* cleaning config file */
  if (ctx->config.ldap_uri != NULL) {
    free(ctx->config.ldap_uri);
  }
  if (ctx->config.ldap_bind_dn != NULL) {
    free(ctx->config.ldap_bind_dn);
  }
  if (ctx->config.ldap_bind_pw != NULL) {
    free(ctx->config.ldap_bind_pw);
  }
  if (ctx->config.ldap_base_dn != NULL) {
    free(ctx->config.ldap_base_dn);
  }
  if (ctx->config.ldap_tls_cacertfile != NULL) {
    free(ctx->config.ldap_tls_cacertfile);
  }
  if (ctx->config.ldap_tls_cacertdir != NULL) {
    free(ctx->config.ldap_tls_cacertdir);
  }
  if (ctx->config.ldap_tls_ciphers != NULL) {
    free(ctx->config.ldap_tls_ciphers);
  }
  if (ctx->config.ldap_tls_cert != NULL) {
    free(ctx->config.ldap_tls_cert);
  }
  if (ctx->config.ldap_tls_key != NULL) {
    free(ctx->config.ldap_tls_key);
  }
  if (ctx->config.ldap_sasl_mechanism != NULL) {
    free(ctx->config.ldap_sasl_mechanism);
  }
  if (ctx->config.ldap_login_attr != NULL) {
    free(ctx->config.ldap_login_attr);
  }
  if (ctx->config.pam_conf_file != NULL) {
    free(ctx->config.pam_conf_file);
  }
  if (ctx->ctx_vector != NULL) {
    free(ctx->ctx_vector);
  }
  free(ctx);
}

/*!
 ** @brief cleanup_mod_ctx is the cleanup function for the module context
 ** 
 ** this function is called by the application(login, gdm...) when calling pam_end().
 **
 ** @param pamh the PAM context handler for this module
 ** @param data the contextual data to clean
 ** @param error_status the context of the cleanup execution
 */
static void cleanup_mod_ctx(pam_handle_t *pamh,
                            void *data,
                            int error_status)
{
  if (error_status == PAM_DATA_REPLACE) {
    pam_syslog(pamh, LOG_INFO, "replacing contextual data. Cleaning old one.");
  }
  clean_configuration((struct pam_module_ctx*)data);
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
    if (config->pam_debug == true) {
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
    } else if (!strcasecmp(k, "pam_user_mgmt")) {
      config->pam_user_mgmt = (user_tristate_t)atol(v);
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
                                   const char *name,
                                   int argc __attribute__((unused)),
                                   const char **argv __attribute__((unused)),
                                   const void *pam_ctx)
{
  LDAP *ld;
  const struct pam_module_ctx *ctx = (const struct pam_module_ctx*)pam_ctx;
  struct berval creds;
  const pam_devid_config_t *pam_args = &(ctx->config);
  creds.bv_val = pam_args->ldap_bind_pw;
  creds.bv_len = strlen(pam_args->ldap_bind_pw); /* Not NULL, checked during config load */
  LDAPMessage *msg = NULL;
  union u_foo foo;
  char *ldap_filter = NULL;
  int  res;
  LDAPMessage *entry = NULL;
  struct berval **entryval;
  const char *device = NULL;

  ldap_filter = malloc(128);
  snprintf(ldap_filter, 127, "(%s=%s)", pam_args->ldap_login_attr, name);
  /* FIXME: to be replaced by a proper conf */
  foo.const_attr = ldap_attributes;

  /* initialize the ldap library */
  if ((res = ldap_initialize(&ld, pam_args->ldap_uri)) != 0) {
    if (pam_args->pam_debug == true) {
      pam_syslog(pamh, LOG_ERR, "ldap_init failed");
    }
    goto error_init;
  }
  /* set ldap option (protocol version) */
  if (ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &(pam_args->ldap_version)) != LDAP_OPT_SUCCESS)
  {
    if (pam_args->pam_debug) {
      pam_syslog(pamh, LOG_ERR, "ldap_set_option failed!");
    }
    goto error_init;
  }
  /* binding to LDAP server */
  if (ldap_sasl_bind_s(ld, pam_args->ldap_bind_dn,
                       NULL, /* SIMPLE authentication (no SASL) */
                       &creds,
                       NULL, NULL, NULL) /* No SSL */
                       != LDAP_SUCCESS ) {
    if (pam_args->pam_debug) {
      pam_syslog(pamh, LOG_ERR, "ldap_bind failed!");
    }
    goto error_init;
  }
  /* Let's search for user, and get uid and devid */
  res = ldap_search_ext_s(ld,
                          pam_args->ldap_base_dn,
                          LDAP_SCOPE_SUB,
                          ldap_filter, /* filter: const char* */
                          foo.attr,
                          0,
                          NULL, /* no specified timeout */
                          NULL, NULL, /* no SSL */
                          12 /* max entries*/,
                          &msg);
  if (res != LDAP_SUCCESS) {
    goto error_bind;
  }
  /* count the number of returned entry (should be one - the user data)*/
  if (ldap_count_entries(ld, msg) == 0) {
    pam_syslog(pamh, LOG_ERR, "no entry found!");
    goto error_request;
  }
  /* get the first user entry content */
  entry = ldap_first_entry(ld, msg);
  if (entry == NULL) {
    pam_syslog(pamh, LOG_ERR, "entry is NULL!");
    goto error_request;
  }
  /*** From here, the code is not ineresting. The uid number is got, not a list of devices id */
  entryval = ldap_get_values_len(ld, entry, "uidNumber");
  if (!entryval) {
    pam_syslog(pamh, LOG_ERR, "entry uidNumber not found in LDAP");
  }
  pam_syslog(pamh, LOG_INFO, "uid found for user %s: %s", name, entryval[0]->bv_val);
  if (strtol(entryval[0]->bv_val, NULL, 10) < pam_args->pam_min_uid) {
    if (pam_args->pam_debug == true) {
      pam_syslog(pamh, LOG_INFO, "uid (%s) smaller than minimum requested (%d)", entryval[0]->bv_val, pam_args->pam_min_uid);
      goto nodata;
    }
  }
  /* uid is in allowed block. Get allowed devices */
  __push_device(pamh, name, device);
  /* finished */
  ldap_msgfree(msg);
  /* unbind from LDAP server */
  res = ldap_unbind_ext(ld, NULL, NULL);
  if (res != 0) {
    pam_syslog(pamh, LOG_ERR, "ldap_unbind_s: %s", ldap_err2string(res));
    goto error_init;
  }
  pam_syslog(pamh, LOG_INFO, "request from LDAP done");
  free(ldap_filter);
  return 0;

  /* error management */
nodata:
error_request:
  ldap_msgfree(msg);
error_bind:
  ldap_unbind_ext(ld, NULL, NULL);
error_init:
  free(ldap_filter);
return 1;
}


/*!
 ** @brief load_all_options parse the pam module arguments & config file
 **
 ** @param pamh the PAM module handler, for pam_syslog
 ** @param argc the module argc
 ** @param argv the module argv
 ** @param pam_args the pam arguments & configuration structure
 **
 ** @return PAM_SUCCESS if correctly done, of PAM_FAILED if not properly treated
 */
static
int load_all_options(pam_handle_t *pamh, int argc, const char **argv,
                     pam_devid_config_t *pam_args)
{
  int i;
  int ret = PAM_SERVICE_ERR;

  assert(argc >= 0);
  for (i = 0; i < argc; i++)
    assert(argv[i] != NULL);

  /* first, set default values */
  pam_args->pam_debug           = false;
  pam_args->ldap_version        = 3;
  pam_args->pam_conf_loaded     = false;

  for (i = 0; i < argc; ++i) {
    if (strcasecmp("debug", argv[i]) == 0) {
      pam_args->pam_debug = true;
    }
    else if (strncmp("config=", argv[i], 7) == 0 && strlen(argv[i]) > 7) {
      /* get conf file ... */
      ret = load_configuration(pamh, &(argv[i][7]), pam_args); /* ... and load */
    } else {
      pam_syslog(pamh, LOG_ERR, "unknown pam_devid option \"%s\"\n", argv[i]);
    }
  }
  if (pam_args->pam_conf_loaded == false) {
    ret = load_configuration(pamh, "/etc/pam_devid.conf", pam_args); /* ... and load from std file if no file given in arg */
  }
  return ret;
}

/*!
 ** @brief is_already_logged check if the user is already logged in locally
 ** 
 ** @param name the user name, given by PAM
 ** @param pamh the pam handler for this module
 ** 
 ** @return 1 if the user is already logged in, or 0
 */
static int is_already_logged(const char *name, pam_handle_t *pamh)
{
  int val = 0;
  int fd;
  struct utmp utmp;

  fd = open("/var/run/utmp", O_RDONLY, 0);
  if (fd == -1) {
    pam_syslog(pamh, LOG_ERR, "Unable to open utmp file to check for user presence");
    goto end;
  }
  /* check if the user is already logged in using utmp. If logged in, then just leave */
  while (read(fd, (char*)&utmp, sizeof(struct utmp)) == sizeof(struct utmp)) {
    if (utmp.ut_type == USER_PROCESS) {
      if (strcmp(utmp.ut_name, name) == 0) {
        if (strcmp(utmp.ut_line, ":0") == 0 || // used by kdm, to be checked for gdm/xdm
            strcmp(utmp.ut_host, ":0") == 0) // used by terms
        {
          pam_syslog(pamh, LOG_INFO, "user %s is already logged in, on tty %s from host %s", utmp.ut_name, utmp.ut_line, utmp.ut_host);
          val++;
        }
      }
    }
  }
  close(fd);
end:
  return val;
}

/*!
 ** @brief is_last_logout specify if the given user id being logged out is currently closing its last session.
 ** 
 ** If the currently closed session is the last one of the given user, then
 ** return 1.
 **
 ** @param name the user name
 ** @param pamh the current module pam handler
 ** 
 ** @return 1 or 0
 */
static int is_last_logout(const char *name, pam_handle_t *pamh)
{
  int sesscount;
  int res = 0;

  if ((sesscount = is_already_logged(name, pamh)) > 1) {
    pam_syslog(pamh, LOG_INFO, "there is %d other opened sessions for user %s. ACL not cleaned.", sesscount, name);
  } else {
    res = 1;
  }
  return res;
}

/*!
 ** @brief other_local_user_logged check if there is other local user(s) already logged in locally
 ** 
 ** @param name the user name, given by PAM
 ** @param pamh the pam handler for this module
 ** 
 ** @return 1 if there is one or more other local users, or 0
 */
static int other_local_user_logged(const char *name, pam_handle_t *pamh)
{
  int val = 0;
  int fd;
  struct utmp utmp;

  fd = open("/var/run/utmp", O_RDONLY, 0);
  if (fd == -1) {
    pam_syslog(pamh, LOG_ERR, "Unable to open utmp file to check for user presence");
    goto end;
  }
  /* check if the user is already logged in using utmp. If logged in, then just leave */
  while (read(fd, (char*)&utmp, sizeof(struct utmp)) == sizeof(struct utmp)) {
    if (utmp.ut_type == USER_PROCESS) {
      if (strcmp(utmp.ut_name, name) != 0) {
        if (strcmp(utmp.ut_line, ":0") == 0 || // used by kdm, to be checked for gdm/xdm
            strcmp(utmp.ut_host, ":0") == 0) // used by terms
        {
          pam_syslog(pamh, LOG_INFO, "user %s is already logged in, on tty %s from host %s", utmp.ut_name, utmp.ut_line, utmp.ut_host);
          val++;
        } else if (strncmp(utmp.ut_line, "tty", 3) == 0) { // logged on local text terminal
          pam_syslog(pamh, LOG_INFO, "user %s is already logged in, on text tty %s", utmp.ut_name, utmp.ut_line);
          val++;
        }
      }
    }
  }
  // FIXME: if root or any LOCAL user (not LDAP) is logged, this function also return TRUE.
  close(fd);
end:
  return val;
}

static void clean_policy(pam_handle_t *pamh, const char * name)
{
  /*
  ** call underlying policy management module, depending on the configuration
  ** (check configure --help)
  */
  __clean_policy(pamh, name);
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
  const char *name = NULL;
  int devid_res = PAM_SERVICE_ERR;
  int ctx_res;
  const void *data;
  struct pam_module_ctx *module_ctx = NULL;

  /* get the user name... */
  devid_res = pam_get_user(pamh, &name, NULL);
  if (devid_res != PAM_SUCCESS || name == NULL) {
    pam_syslog(pamh, LOG_ERR, "unable to get back user name");
    return devid_res;
  }
  /* load LDAP infos only if user is not yet logged locally on the host */
  if (!is_already_logged(name, pamh)) {
    /* first load module data. If inexistent, fulfill and load it */
    ctx_res = pam_get_data(pamh, MODNAME, &data);
    if (ctx_res == PAM_NO_MODULE_DATA) { // no data for now, create new context
      module_ctx = malloc(sizeof(struct pam_module_ctx));
      if (NULL == module_ctx) {
        pam_syslog(pamh, LOG_ERR, "error during the allocation of module context");
        goto end;
      }
      /* load all options (arguments & config file) */
      devid_res = load_all_options(pamh, argc, argv, &(module_ctx->config));
      if (devid_res != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "error during configuration, leaving.");
        goto error_load;
      }
      if (module_ctx->config.pam_debug) {
        pam_syslog(pamh, LOG_INFO, "user %s session opened", name);
      }
      /* ok context created. Now push it to pam context manager */
      pam_set_data(pamh, MODNAME, (void**)&module_ctx, cleanup_mod_ctx);
      data = &module_ctx;
    }
    if (module_ctx->config.pam_user_mgmt == USER_FIRST_LOGGED) {
      if (!other_local_user_logged(name, pamh)) {
        clean_policy(pamh, NULL);
        request_devid_from_ldap(pamh, name, argc, argv, data);
      } else {
        /*
        ** if another local user exists, ignore the current one. While a local
        ** user exists, the policy is unchanged. All users need to log out
        ** before loading a new policy
        */
        pam_syslog(pamh, LOG_INFO, "at least one previously logged in user exists. Policy not modified");
      }
    } else if (module_ctx->config.pam_user_mgmt == USER_MERGE) {
      /* merge currently logging in user policy with possible current one */
      request_devid_from_ldap(pamh, name, argc, argv, data);
    } else if (module_ctx->config.pam_user_mgmt == USER_LAST_LOGGED) {
      /*
      ** New user is logging in. Clean old config and load new one.
      */
      clean_policy(pamh, NULL);
      request_devid_from_ldap(pamh, name, argc, argv, data);
    }
  }
end:
  return devid_res;
error_load:
  free(module_ctx);
  return PAM_SERVICE_ERR;
}

/*!
 ** @brief pam_sm_close_session is called when a user session is closed
 ** 
 ** @param pamh the current pam module handler, given by PAM 
 ** @param flags the PAM flags (NULL or PAM_SILENT)
 ** @param argc the module's arguments list counter 
 ** @param argv the module's arguments list
 ** 
 ** @return one of pam return codes depending on the treatments results
 */
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh,
                                    int          flags __attribute__((unused)),
                                    int          argc __attribute__((unused)),
                                    const char** argv __attribute__((unused)))
{
  const char *name;
  int ret;
  int devid_res = PAM_SERVICE_ERR;
  int ctx_res;
  const void *data;

  ctx_res = pam_get_data(pamh, MODNAME, &data);
  if (ctx_res == PAM_NO_MODULE_DATA) { // no data found ?!?
    pam_syslog(pamh, LOG_INFO, "No module data found!");
    goto end;
  }
  ret = pam_get_user(pamh, &name, NULL);
  if (ret != PAM_SUCCESS || name == NULL) {
    pam_syslog(pamh, LOG_ERR, "unable to get back user name");
    return ret;
  }
  pam_syslog(pamh, LOG_INFO, "user %s session closed", name);
  /* if there is more than one currently opened local sessions, then ACL are maintained */
  if (is_last_logout(name, pamh)) {
    // clean ACL for current user (FIXME: not yet supporting multiple local users management - see pam_user_mgmt option)
    clean_policy(pamh, name);
  }
  /*
  ** Okay nothing is done here. We need to manage session counter in order to
  ** update local key list only if a _new_ user is logging in, not a
  ** previously logged in anther call.
  ** As a consequence, we need to count the number of session open/close
  ** in order to know if wee have to load a new keylist or not.
  */
  devid_res = PAM_SUCCESS;
end:
  return devid_res;
}

