/* pam_synafp.c - PAM authentication module backed by the synafp driver.
 *
 * Typical use, as the first line of an auth stack:
 *
 *   auth  sufficient  pam_synafp.so  timeout=15 retries=3
 *   auth  include     system-auth
 *
 * The module deliberately returns PAM_IGNORE (rather than an error) whenever
 * fingerprint authentication simply is not available - no sensor, no enrolled
 * finger, no permission - so that a `sufficient` line falls through to the
 * password prompt instead of locking anybody out.
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

#define DEFAULT_TIMEOUT_S  15
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

/* Send a line of text to the user through the PAM conversation. */
static void tell(pam_handle_t *pamh, const struct opts *o, int style, const char *msg)
{
    if (o->quiet && style == PAM_TEXT_INFO)
        return;
    pam_prompt(pamh, style, NULL, "%s", msg);
}

struct cb_ctx {
    pam_handle_t      *pamh;
    const struct opts *o;
    int                announced;
};

static int pam_progress(syna_event ev, int arg, void *user)
{
    struct cb_ctx *c = user;

    switch (ev) {
    case SYNA_EV_READY:
        if (!c->announced) {
            tell(c->pamh, c->o, PAM_TEXT_INFO, "Touch the fingerprint sensor.");
            c->announced = 1;
        }
        break;
    case SYNA_EV_RETRY:
        tell(c->pamh, c->o, PAM_ERROR_MSG,
             "Fingerprint not readable, try again.");
        break;
    default:
        break;
    }
    (void)arg;
    return 0;
}

/* Does this user have anything enrolled? Answering "no" lets us fall through
 * to the password prompt silently. */
static int user_has_template(syna_dev *d, const char *user, int *known)
{
    syna_template t[BMKT_MAX_TEMPLATES];
    int n = 0, i, rc;

    *known = 0;
    rc = syna_list(d, t, (int)(sizeof t / sizeof t[0]), &n);
    if (rc != SYNA_OK)
        return rc;
    for (i = 0; i < n; i++) {
        if (!strcmp(t[i].user_id, user)) {
            *known = 1;
            break;
        }
    }
    return SYNA_OK;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv)
{
    struct opts o;
    struct cb_ctx cbc;
    const char *user = NULL;
    syna_dev *d = NULL;
    syna_match m;
    int rc, attempt, ret = PAM_AUTHINFO_UNAVAIL;
    int known = 1, listed_ok;

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
        /* No sensor, or no permission to use it: let other modules decide. */
        return PAM_IGNORE;
    }

    syna_set_timeout(d, o.timeout_s * 1000u);

    /* If enumeration works, use it to skip users with no enrolled finger.
     * If it does not, fall through and let the sensor answer. */
    listed_ok = (user_has_template(d, user, &known) == SYNA_OK);
    if (listed_ok && !known) {
        if (o.debug)
            pam_syslog(pamh, LOG_DEBUG, "synafp: no template for '%s'", user);
        syna_close(d);
        return PAM_IGNORE;
    }

    cbc.pamh = pamh;
    cbc.o = &o;
    cbc.announced = 0;

    for (attempt = 0; attempt < o.retries; attempt++) {
        cbc.announced = 0;
        rc = syna_verify(d, user, &m, pam_progress, &cbc);

        if (rc == SYNA_OK && m.matched) {
            tell(pamh, &o, PAM_TEXT_INFO, "Fingerprint accepted.");
            pam_syslog(pamh, LOG_INFO, "synafp: '%s' authenticated by fingerprint", user);
            ret = PAM_SUCCESS;
            break;
        }

        if (rc == SYNA_OK && !m.matched) {
            ret = PAM_AUTH_ERR;
            if (attempt + 1 < o.retries)
                tell(pamh, &o, PAM_ERROR_MSG, "Fingerprint did not match.");
            continue;
        }

        if (rc == SYNA_ERR_TIMEOUT || rc == SYNA_ERR_CANCELLED) {
            /* The user chose not to use the sensor: hand over to the next
             * module rather than failing the whole stack. */
            ret = PAM_IGNORE;
            break;
        }

        if (SYNA_IS_SENSOR_ERR(rc) &&
            SYNA_SENSOR_STATUS(rc) == BMKT_STATUS_NO_RECORD_EXISTS) {
            ret = PAM_IGNORE;
            break;
        }

        pam_syslog(pamh, LOG_NOTICE, "synafp: verification error: %s",
                   syna_strerror(rc));
        ret = PAM_AUTHINFO_UNAVAIL;
        break;
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
