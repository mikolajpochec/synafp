/* synafp_auth - setuid helper for unprivileged PAM callers.
 *
 * Screen lockers run as the user who is locked out, not as root, so a PAM
 * module loaded into them cannot read the DMI serial that seeds the sensor's
 * session key. pam_unix has the same problem and solves it with the setuid
 * unix_chkpwd; this is the equivalent for synafp.
 *
 *   synafp-auth <username>
 *
 * Exit status: 0 the finger is that user's, 1 it is not, 2 fingerprint
 * authentication is unavailable, 3 the request was refused.
 *
 * Being setuid, this does as little as possible while privileged: open the
 * device, derive the key, then drop root before anything parses a byte that
 * came from the sensor.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "synafp.h"

#define EXIT_MATCH        0
#define EXIT_NO_MATCH     1
#define EXIT_UNAVAILABLE  2
#define EXIT_REFUSED      3

/* A setuid program inherits whatever file descriptors its caller left it. If
 * 0, 1 or 2 are closed, the first file we open lands on one of them and stray
 * writes corrupt it. Make sure all three exist before doing anything else. */
static void secure_fds(void)
{
    int fd;

    for (fd = 0; fd < 3; fd++) {
        if (fcntl(fd, F_GETFD) == -1) {
            int n = open("/dev/null", O_RDWR);
            if (n < 0)
                _exit(EXIT_UNAVAILABLE);
            if (n != fd) {
                dup2(n, fd);
                close(n);
            }
        }
    }
}

int main(int argc, char **argv)
{
    const char *want;
    struct passwd *pw;
    syna_dev *d = NULL;
    syna_match_result m;
    int rc;

    secure_fds();

    /* Nothing here reads the environment, and leaving it populated only gives
     * a caller influence over libraries loaded into a privileged process. */
    if (clearenv() != 0)
        return EXIT_UNAVAILABLE;

    if (argc != 2)
        return EXIT_REFUSED;
    want = argv[1];
    if (!*want || strlen(want) > 256)
        return EXIT_REFUSED;

    /* A caller may only ask about itself. Otherwise this would answer
     * "whose finger is this?" for any account, to anyone. */
    if (getuid() != 0) {
        pw = getpwuid(getuid());
        if (!pw || !pw->pw_name || strcmp(pw->pw_name, want) != 0) {
            openlog("synafp-auth", LOG_PID, LOG_AUTH);
            syslog(LOG_WARNING, "uid %u asked to verify '%s': refused",
                   (unsigned)getuid(), want);
            closelog();
            return EXIT_REFUSED;
        }
    }

    rc = syna_open(&d, NULL, 0);
    if (rc != SYNA_OK)
        return EXIT_UNAVAILABLE;

    /* Everything privileged is done. Shed root before the sensor's replies
     * reach a single parser. */
    if (syna_drop_privileges() != SYNA_OK) {
        syna_close(d);
        return EXIT_UNAVAILABLE;
    }

    syna_set_timeout(d, 15000);
    rc = syna_verify(d, want, &m);
    syna_close(d);

    if (rc == SYNA_ERR_NOT_FOUND)
        return EXIT_UNAVAILABLE;            /* nothing enrolled for this user */
    if (rc != SYNA_OK)
        return EXIT_UNAVAILABLE;

    return m.matched ? EXIT_MATCH : EXIT_NO_MATCH;
}
