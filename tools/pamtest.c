/* pamtest.c - exercise a PAM stack without touching a real one.
 *
 *   sudo ./pamtest [service] [user]
 *
 * Defaults to the "synafp-test" service, which dist/synafp-test points
 * straight at the freshly built module. Nothing in /etc/pam.d that matters is
 * involved, so a broken module cannot lock anybody out.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#define _POSIX_C_SOURCE 200809L

#include <security/pam_appl.h>

#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Relay module messages to the terminal; refuse to answer password prompts so
 * a misconfigured stack cannot silently fall through to one. */
static int conv_fn(int n, const struct pam_message **msg,
                   struct pam_response **resp, void *appdata)
{
    struct pam_response *r;
    int i;

    (void)appdata;
    r = calloc((size_t)n, sizeof *r);
    if (!r)
        return PAM_BUF_ERR;

    for (i = 0; i < n; i++) {
        switch (msg[i]->msg_style) {
        case PAM_TEXT_INFO:
            printf("  [info]  %s\n", msg[i]->msg);
            break;
        case PAM_ERROR_MSG:
            printf("  [error] %s\n", msg[i]->msg);
            break;
        default:
            printf("  [prompt suppressed] %s\n", msg[i]->msg);
            r[i].resp = NULL;
            break;
        }
        fflush(stdout);
    }
    *resp = r;
    return PAM_SUCCESS;
}

int main(int argc, char **argv)
{
    const char *service = (argc > 1) ? argv[1] : "synafp-test";
    const char *user;
    struct pam_conv conv = { conv_fn, NULL };
    pam_handle_t *pamh = NULL;
    int rc;

    if (argc > 2) {
        user = argv[2];
    } else {
        const char *s = getenv("SUDO_USER");
        if (s && *s) {
            user = s;
        } else {
            struct passwd *pw = getpwuid(getuid());
            user = (pw && pw->pw_name) ? pw->pw_name : "root";
        }
    }

    printf("service=%s user=%s\n", service, user);

    rc = pam_start(service, user, &conv, &pamh);
    if (rc != PAM_SUCCESS) {
        fprintf(stderr, "pam_start: %s\n", pam_strerror(pamh, rc));
        return 1;
    }

    rc = pam_authenticate(pamh, 0);
    printf("\npam_authenticate -> %d (%s)\n", rc, pam_strerror(pamh, rc));

    switch (rc) {
    case PAM_SUCCESS:
        printf("RESULT: authenticated by fingerprint\n");
        break;
    case PAM_AUTH_ERR:
        printf("RESULT: finger read, but rejected\n");
        break;
    case PAM_IGNORE:
        printf("RESULT: module declined (unavailable) - a real stack would "
               "fall through to the password prompt\n");
        break;
    default:
        printf("RESULT: %s\n", pam_strerror(pamh, rc));
        break;
    }

    pam_end(pamh, rc);
    return rc == PAM_SUCCESS ? 0 : 1;
}
