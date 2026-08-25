/* synafp_cli.c - command line front-end for the synafp driver.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#define _POSIX_C_SOURCE 200809L
#include "synafp.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <pwd.h>

#define EXIT_OK       0
#define EXIT_FAIL     1
#define EXIT_NOMATCH  2

static syna_dev *g_dev;
static volatile sig_atomic_t g_interrupted;
static int g_quiet;
static int g_last_progress = -1;

static void on_sigint(int sig)
{
    (void)sig;
    g_interrupted = 1;
    if (g_dev)
        syna_cancel(g_dev);
}

static void install_signals(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sigint;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

static const char *current_user(void)
{
    struct passwd *pw = getpwuid(getuid());
    return (pw && pw->pw_name) ? pw->pw_name : "user";
}

static void say(const char *fmt, ...)
{
    va_list ap;
    if (g_quiet) return;
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
    fputc('\n', stdout);
    fflush(stdout);
}

static int progress_cb(syna_event ev, int arg, void *user)
{
    (void)user;
    if (g_interrupted)
        return 1;
    if (g_quiet)
        return 0;

    switch (ev) {
    case SYNA_EV_READY:
        printf("Place your finger on the sensor...\n");
        break;
    case SYNA_EV_FINGER_DOWN:
        printf("  finger detected\n");
        break;
    case SYNA_EV_FINGER_UP:
        printf("  lift your finger\n");
        break;
    case SYNA_EV_CAPTURE_OK:
        printf("  image captured\n");
        break;
    case SYNA_EV_ENROLL_PROGRESS:
        if (arg != g_last_progress) {
            g_last_progress = arg;
            printf("  enrolment %d%%\n", arg);
        }
        break;
    case SYNA_EV_DELETE_PROGRESS:
        printf("  erasing %d%%\n", arg);
        break;
    case SYNA_EV_RETRY:
        printf("  that touch was not usable, try again%s\n",
               arg ? " (adjust your finger position)" : "");
        break;
    }
    fflush(stdout);
    return 0;
}

static void usage(FILE *f)
{
    fprintf(f,
"synafp - userspace driver for Synaptics match-on-chip fingerprint sensors\n"
"\n"
"Usage: synafp [global options] <command> [arguments]\n"
"\n"
"Commands:\n"
"  info                       show sensor identity, firmware and storage use\n"
"  list                       list fingerprints stored on the sensor\n"
"  enroll <finger>            record a new fingerprint\n"
"  verify [finger]            check a finger against this user's templates\n"
"  identify                   match a finger against every enrolled user\n"
"  delete <finger>            remove one stored fingerprint\n"
"  clear                      erase every fingerprint on the sensor\n"
"  status                     dump the sensor's raw status report\n"
"  power-down                 put the sensor into its low power state\n"
"\n"
"Finger names:\n"
"  left-thumb  left-index  left-middle  left-ring  left-little\n"
"  right-thumb right-index right-middle right-ring right-little\n"
"  (a number from 1 to 10 works too)\n"
"\n"
"Global options:\n"
"  -u, --user <name>          operate on this user id (default: the caller)\n"
"  -s, --serial <serial>      select a specific sensor\n"
"  -t, --timeout <seconds>    how long to wait for a finger (0 = forever)\n"
"  -r, --reset                USB-reset the sensor before talking to it\n"
"  -q, --quiet                only report the final result\n"
"  -v, --verbose              protocol tracing (repeat for hex dumps)\n"
"  -h, --help                 this text\n"
"\n"
"Exit status: 0 success, 1 error, 2 no match.\n");
}

static int cmd_info(syna_dev *d)
{
    syna_fw_version fw;
    syna_ace_version av;
    syna_capacity cap;
    int rc, i;

    printf("Sensor        : Synaptics %04x (serial %s)\n",
           syna_product_id(d), syna_serial(d));

    rc = syna_fw_version_get(d, &fw);
    if (rc == SYNA_OK) {
        printf("Firmware      : %u.%u patch %u (build %u)\n",
               fw.version_major, fw.version_minor, fw.patch, fw.build_num);
        printf("Silicon       : rev %u, platform %u, product %u, type 0x%02x\n",
               fw.silicon_rev, fw.platform, fw.product, fw.device_type);
        printf("Security      : 0x%04x%s\n", fw.security,
               fw.security ? "" : " (no host-side pairing required)");
        printf("Sensor serial : ");
        for (i = 0; i < 6; i++) printf("%02x", fw.serial_number[i]);
        printf("\n");
    } else {
        printf("Firmware      : unavailable (%s)\n", syna_strerror(rc));
    }

    rc = syna_ace_version_get(d, &av);
    if (rc == SYNA_OK)
        printf("Module        : part %s, supplier %s, %02u/%02u patch %u\n",
               av.part, av.supplier_id, av.week, av.year, av.patch);

    rc = syna_capacity_get(d, &cap);
    if (rc == SYNA_OK) {
        printf("Templates     : %u of %u slots free\n", cap.empty, cap.total);
        if (cap.has_extended)
            printf("                %u bad slots, %u corrupt templates\n",
                   cap.bad_slots, cap.corrupt_templates);
    } else {
        printf("Templates     : unavailable (%s)\n", syna_strerror(rc));
    }
    return EXIT_OK;
}

static int cmd_list(syna_dev *d, const char *filter_user)
{
    syna_template t[BMKT_MAX_TEMPLATES];
    int n = 0, rc, i, shown = 0;

    rc = syna_list(d, t, (int)(sizeof t / sizeof t[0]), &n);
    if (rc != SYNA_OK) {
        fprintf(stderr, "synafp: cannot list templates: %s\n", syna_strerror(rc));
        return EXIT_FAIL;
    }
    for (i = 0; i < n; i++) {
        if (filter_user && strcmp(filter_user, t[i].user_id) != 0)
            continue;
        printf("%-24s %-14s status=%u\n",
               t[i].user_id, syna_finger_name(t[i].finger_id), t[i].template_status);
        shown++;
    }
    if (!shown)
        say("No fingerprints are enrolled%s%s.",
            filter_user ? " for " : "", filter_user ? filter_user : "");
    return EXIT_OK;
}

int main(int argc, char **argv)
{
    const char *user = NULL, *serial = NULL;
    unsigned flags = 0;
    long timeout_s = -1;
    int verbose = 0, i, rc, ret;
    const char *cmd;
    syna_dev *d = NULL;

    for (i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (a[0] != '-' || !a[1])
            break;
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(stdout); return EXIT_OK; }
        else if (!strcmp(a, "-q") || !strcmp(a, "--quiet")) g_quiet = 1;
        else if (!strcmp(a, "-v") || !strcmp(a, "--verbose")) verbose++;
        else if (!strcmp(a, "-r") || !strcmp(a, "--reset")) flags |= SYNA_OPEN_RESET;
        else if ((!strcmp(a, "-u") || !strcmp(a, "--user")) && i + 1 < argc) user = argv[++i];
        else if ((!strcmp(a, "-s") || !strcmp(a, "--serial")) && i + 1 < argc) serial = argv[++i];
        else if ((!strcmp(a, "-t") || !strcmp(a, "--timeout")) && i + 1 < argc) timeout_s = atol(argv[++i]);
        else { fprintf(stderr, "synafp: unknown option %s\n", a); usage(stderr); return EXIT_FAIL; }
    }

    if (i >= argc) { usage(stderr); return EXIT_FAIL; }
    cmd = argv[i++];

    if (verbose)
        syna_set_debug(verbose);
    if (!user)
        user = current_user();

    install_signals();

    rc = syna_open(&d, serial, flags);
    if (rc != SYNA_OK) {
        fprintf(stderr, "synafp: %s\n", syna_strerror(rc));
        if (rc == SYNA_ERR_ACCESS)
            fprintf(stderr,
                "synafp: install the udev rule (70-synafp.rules) or run as root.\n");
        return EXIT_FAIL;
    }
    g_dev = d;
    if (timeout_s >= 0)
        syna_set_timeout(d, (unsigned)(timeout_s * 1000));

    ret = EXIT_OK;

    if (!strcmp(cmd, "info") || !strcmp(cmd, "probe")) {
        ret = cmd_info(d);

    } else if (!strcmp(cmd, "list")) {
        ret = cmd_list(d, NULL);

    } else if (!strcmp(cmd, "enroll")) {
        int finger;
        if (i >= argc) {
            fprintf(stderr, "synafp: enroll needs a finger name, e.g. right-index\n");
            ret = EXIT_FAIL;
        } else if ((finger = syna_finger_from_name(argv[i])) < 0) {
            fprintf(stderr, "synafp: '%s' is not a finger name\n", argv[i]);
            ret = EXIT_FAIL;
        } else {
            say("Enrolling %s for '%s'.", syna_finger_name((uint8_t)finger), user);
            rc = syna_enroll(d, user, (uint8_t)finger, progress_cb, NULL);
            if (rc == SYNA_OK) {
                say("Enrolment complete.");
            } else {
                fprintf(stderr, "synafp: enrolment failed: %s\n", syna_strerror(rc));
                ret = EXIT_FAIL;
            }
        }

    } else if (!strcmp(cmd, "verify")) {
        syna_match m;
        rc = syna_verify(d, user, &m, progress_cb, NULL);
        if (rc != SYNA_OK) {
            fprintf(stderr, "synafp: verification failed: %s\n", syna_strerror(rc));
            ret = EXIT_FAIL;
        } else if (m.matched) {
            say("Match: %s (%s), score %.2f", m.user_id[0] ? m.user_id : user,
                syna_finger_name(m.finger_id), m.score);
            ret = EXIT_OK;
        } else {
            say("No match.");
            ret = EXIT_NOMATCH;
        }

    } else if (!strcmp(cmd, "identify")) {
        syna_template t[BMKT_MAX_TEMPLATES];
        const char *ids[BMKT_MAX_TEMPLATES];
        int n = 0, k, nid = 0;
        syna_match m;

        rc = syna_list(d, t, (int)(sizeof t / sizeof t[0]), &n);
        if (rc != SYNA_OK) {
            fprintf(stderr, "synafp: cannot enumerate templates: %s\n", syna_strerror(rc));
            ret = EXIT_FAIL;
        } else if (n == 0) {
            say("No fingerprints are enrolled.");
            ret = EXIT_NOMATCH;
        } else {
            /* one entry per distinct user id */
            for (k = 0; k < n; k++) {
                int j, dup = 0;
                for (j = 0; j < nid; j++)
                    if (!strcmp(ids[j], t[k].user_id)) { dup = 1; break; }
                if (!dup)
                    ids[nid++] = t[k].user_id;
            }
            rc = syna_identify(d, ids, nid, &m, progress_cb, NULL);
            if (rc != SYNA_OK) {
                fprintf(stderr, "synafp: identification failed: %s\n", syna_strerror(rc));
                ret = EXIT_FAIL;
            } else if (m.matched) {
                say("Match: %s (%s), score %.2f", m.user_id,
                    syna_finger_name(m.finger_id), m.score);
            } else {
                say("No match.");
                ret = EXIT_NOMATCH;
            }
        }

    } else if (!strcmp(cmd, "delete")) {
        int finger;
        if (i >= argc) {
            fprintf(stderr, "synafp: delete needs a finger name\n");
            ret = EXIT_FAIL;
        } else if ((finger = syna_finger_from_name(argv[i])) < 0) {
            fprintf(stderr, "synafp: '%s' is not a finger name\n", argv[i]);
            ret = EXIT_FAIL;
        } else {
            rc = syna_delete(d, user, (uint8_t)finger);
            if (rc == SYNA_OK)
                say("Deleted %s for '%s'.", syna_finger_name((uint8_t)finger), user);
            else {
                fprintf(stderr, "synafp: delete failed: %s\n", syna_strerror(rc));
                ret = EXIT_FAIL;
            }
        }

    } else if (!strcmp(cmd, "clear")) {
        rc = syna_clear(d, progress_cb, NULL);
        if (rc == SYNA_OK)
            say("All fingerprints erased from the sensor.");
        else {
            fprintf(stderr, "synafp: clear failed: %s\n", syna_strerror(rc));
            ret = EXIT_FAIL;
        }

    } else if (!strcmp(cmd, "status")) {
        uint8_t buf[64];
        size_t len = 0;
        rc = syna_sensor_status(d, buf, sizeof buf, &len);
        if (rc == SYNA_OK) {
            size_t k;
            printf("Sensor status (%zu bytes):", len);
            for (k = 0; k < len; k++) printf(" %02x", buf[k]);
            printf("\n");
        } else {
            fprintf(stderr, "synafp: status query failed: %s\n", syna_strerror(rc));
            ret = EXIT_FAIL;
        }

    } else if (!strcmp(cmd, "power-down")) {
        rc = syna_power_down(d);
        if (rc == SYNA_OK) say("Sensor powered down.");
        else {
            fprintf(stderr, "synafp: power down failed: %s\n", syna_strerror(rc));
            ret = EXIT_FAIL;
        }

    } else {
        fprintf(stderr, "synafp: unknown command '%s'\n", cmd);
        usage(stderr);
        ret = EXIT_FAIL;
    }

    g_dev = NULL;
    syna_close(d);
    return ret;
}
