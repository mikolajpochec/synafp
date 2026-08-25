/* pam_synafp.c - PAM authentication backed by the synafp driver.
 *
 * Typical use, above the password module:
 *
 *   auth  sufficient  pam_synafp.so  timeout=15 retries=3
 *   auth  include     system-auth
 *
 * The module returns PAM_IGNORE whenever fingerprint authentication is merely
 * *unavailable* - no sensor, nothing enrolled for this user, no permission, or
 * the user pressed Ctrl-C instead of touching the reader. A `sufficient` line
 * therefore falls through to the password prompt rather than locking anyone
 * out. Only a finger that is read but does not belong to the user is an
 * authentication failure.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#define _POSIX_C_SOURCE 200809L

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_appl.h>

#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "synafp.h"

#define DEFAULT_TIMEOUT_S 15
#define DEFAULT_RETRIES    3

struct opts {
    unsigned timeout_s;
    int      retries;
    int      debug;
    int      quiet;
};

static void parse_opts(struct opts *o, int argc, const char **argv)
{
    int i;

    o->timeout_s = DEFAULT_TIMEOUT_S;
    o->retries   = DEFAULT_RETRIES;
    o->debug     = 0;
    o->quiet     = 0;

    for (i = 0; i < argc; i++) {
        if (!strncmp(argv[i], "timeout=", 8))
            o->timeout_s = (unsigned)atoi(argv[i] + 8);
        else if (!strncmp(argv[i], "retries=", 8))
            o->retries = atoi(argv[i] + 8);
        else if (!strcmp(argv[i], "debug"))
            o->debug = 1;
        else if (!strcmp(argv[i], "quiet"))
            o->quiet = 1;
    }
    if (o->retries < 1)
        o->retries = 1;
}

static void tell(pam_handle_t *pamh, const struct opts *o, int style, const char *msg)
{
    if (o->quiet && style == PAM_TEXT_INFO)
        return;
    pam_prompt(pamh, style, NULL, "%s", msg);
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv)
{
    struct opts o;
    const char *user = NULL;
    syna_dev *d = NULL;
    syna_match_result m;
    int rc, attempt, ret = PAM_IGNORE;

    (void)flags;
    parse_opts(&o, argc, argv);

    rc = pam_get_user(pamh, &user, NULL);
    if (rc != PAM_SUCCESS || !user || !*user)
        return PAM_IGNORE;

    if (o.debug)
        syna_set_debug(1);

    rc = syna_open(&d, NULL, 0);
    if (rc != SYNA_OK) {
        if (o.debug)
            pam_syslog(pamh, LOG_DEBUG, "synafp: sensor unavailable: %s",
                       syna_strerror(rc));
        return PAM_IGNORE;
    }

    syna_set_timeout(d, o.timeout_s * 1000u);

    for (attempt = 0; attempt < o.retries; attempt++) {
        tell(pamh, &o, PAM_TEXT_INFO, "Touch the fingerprint sensor.");

        rc = syna_verify(d, user, &m);

        if (rc == SYNA_ERR_NOT_FOUND) {
            /* Nothing enrolled for this user: not our business. */
            if (o.debug)
                pam_syslog(pamh, LOG_DEBUG, "synafp: nothing enrolled for '%s'", user);
            ret = PAM_IGNORE;
            break;
        }

        if (rc == SYNA_ERR_TIMEOUT || rc == SYNA_ERR_CANCELLED) {
            /* The user chose not to use the sensor. */
            ret = PAM_IGNORE;
            break;
        }

        if (rc != SYNA_OK) {
            pam_syslog(pamh, LOG_NOTICE, "synafp: verification error: %s",
                       syna_strerror(rc));
            ret = PAM_IGNORE;
            break;
        }

        if (m.matched) {
            pam_syslog(pamh, LOG_INFO,
                       "synafp: '%s' authenticated by fingerprint", user);
            ret = PAM_SUCCESS;
            break;
        }

        ret = PAM_AUTH_ERR;
        if (attempt + 1 < o.retries)
            tell(pamh, &o, PAM_ERROR_MSG, "Fingerprint not recognised.");
    }

    if (ret == PAM_AUTH_ERR)
        pam_syslog(pamh, LOG_NOTICE, "synafp: fingerprint rejected for '%s'", user);

    syna_close(d);
    return ret;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                              int argc, const char **argv)
{
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
                                int argc, const char **argv)
{
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_IGNORE;
}
