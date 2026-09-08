/* synafp-enroll-helper - child process for D-Bus enrollment.
 *
 *   synafp-enroll-helper <username> <finger_name>
 *
 * Writes status lines to stdout:
 *   enroll-finger-present <touches> <progress>
 *   enroll-compare-scan  <touches> <progress>
 *   enroll-finger-duplicate <touches> <progress>
 *   enroll-result 0|1   (final line)
 *
 * Exit: 0 success, 1 failure, 2 unavailable.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "synafp.h"

static syna_dev *g_dev;

static void on_term(int sig)
{
    (void)sig;
    if (g_dev)
        syna_cancel(g_dev);
}

static void secure_fds(void)
{
    int fd;
    for (fd = 0; fd < 3; fd++) {
        if (fcntl(fd, F_GETFD) == -1) {
            int n = open("/dev/null", O_RDWR);
            if (n < 0) _exit(2);
            if (n != fd) { dup2(n, fd); close(n); }
        }
    }
}

static int enroll_callback(syna_enroll_event ev, int touches, int progress, void *user)
{
    const char *status = NULL;
    (void)user;

    switch (ev) {
    case SYNA_ENROLL_TOUCH:    status = "enroll-finger-present"; break;
    case SYNA_ENROLL_PROGRESS: status = "enroll-compare-scan";   break;
    case SYNA_ENROLL_RETRY:    status = "enroll-finger-duplicate"; break;
    }

    if (status)
        printf("%s %d %d\n", status, touches, progress);
    fflush(stdout);
    return 0;
}

int main(int argc, char **argv)
{
    const char *username, *finger_name;
    uint16_t subtype;
    int subtype_raw;
    syna_dev *d = NULL;
    struct sigaction sa;
    int rc;

    secure_fds();

    if (clearenv() != 0)
        return 2;

    if (argc != 3) {
        fprintf(stderr, "usage: synafp-enroll-helper <user> <finger>\n");
        return 2;
    }

    username = argv[1];
    finger_name = argv[2];

    if (!*username || strlen(username) > 256 || !*finger_name)
        return 2;

    subtype_raw = syna_subtype_from_name(finger_name);
    if (subtype_raw < 0) {
        fprintf(stderr, "synafp-enroll-helper: unknown finger '%s'\n", finger_name);
        return 2;
    }
    subtype = (uint16_t)subtype_raw;

    rc = syna_open(&d, NULL, 0);
    if (rc != SYNA_OK) {
        fprintf(stderr, "synafp-enroll-helper: cannot open sensor: %s\n", syna_strerror(rc));
        printf("enroll-result 0\n");
        fflush(stdout);
        return 1;
    }

    rc = syna_drop_privileges();
    if (rc != SYNA_OK) {
        fprintf(stderr, "synafp-enroll-helper: cannot drop privileges: %s\n", syna_strerror(rc));
        syna_close(d);
        printf("enroll-result 0\n");
        fflush(stdout);
        return 1;
    }

    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_term;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);

    g_dev = d;
    syna_set_timeout(d, 15000);

    rc = syna_enroll(d, username, subtype, enroll_callback, NULL);
    g_dev = NULL;

    printf("enroll-result %d\n", rc == SYNA_OK ? 1 : 0);
    fflush(stdout);

    syna_close(d);
    return rc == SYNA_OK ? 0 : 1;
}
