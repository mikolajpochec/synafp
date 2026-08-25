/* synafp-fprintd - expose the sensor on the fprintd D-Bus interface.
 *
 * Screen lockers and desktop shells do not talk to PAM to light the reader.
 * They talk to fprintd: a locker calls VerifyStart when the lock screen
 * appears, so the sensor is armed and waiting before the user types anything.
 * A PAM module cannot do that, because PAM only runs once the user submits
 * input - which is why fingerprint-through-PAM only ever wakes the reader
 * after a password has been typed.
 *
 * This implements the subset of net.reactivated.Fprint that lockers use, and
 * does the actual verification by running synafp-auth, so the scanning code
 * runs in a short-lived process that can be cancelled by killing it.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include <errno.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>

#include <systemd/sd-bus.h>
#include <systemd/sd-event.h>

#include "synafp.h"

#ifndef SYNAFP_HELPER
#define SYNAFP_HELPER "/usr/local/libexec/synafp-auth"
#endif

#define MANAGER_PATH "/net/reactivated/Fprint/Manager"
#define DEVICE_PATH  "/net/reactivated/Fprint/Device/0"
#define DEVICE_IFACE "net.reactivated.Fprint.Device"

static sd_bus       *bus;
static sd_event     *event;
static char          claimed_user[256];
static pid_t         verify_pid;
static sd_event_source *verify_source;

static void emit_status(const char *result, int done)
{
    syslog(LOG_DEBUG, "VerifyStatus %s done=%d", result, done);
    sd_bus_emit_signal(bus, DEVICE_PATH, DEVICE_IFACE, "VerifyStatus",
                       "sb", result, done);
}

/* The helper's exit status, translated into fprintd's vocabulary. */
static const char *result_for_exit(int code)
{
    switch (code) {
    case 0:  return "verify-match";
    case 1:  return "verify-no-match";
    case 2:  return "verify-unknown-error";   /* no sensor, nothing enrolled, timeout */
    default: return "verify-unknown-error";
    }
}

static int on_verify_exit(sd_event_source *s, const siginfo_t *si, void *userdata)
{
    int code = (si->si_code == CLD_EXITED) ? si->si_status : 2;

    (void)s; (void)userdata;
    verify_pid = 0;
    verify_source = sd_event_source_unref(verify_source);

    emit_status(result_for_exit(code), 1);
    return 0;
}

static int stop_verify(void)
{
    if (verify_pid > 0) {
        kill(verify_pid, SIGTERM);
        waitpid(verify_pid, NULL, 0);
        verify_pid = 0;
    }
    verify_source = sd_event_source_unref(verify_source);
    return 0;
}

/* --- Manager ------------------------------------------------------------ */
static int method_get_default_device(sd_bus_message *m, void *u, sd_bus_error *e)
{
    (void)u; (void)e;
    return sd_bus_reply_method_return(m, "o", DEVICE_PATH);
}

static int method_get_devices(sd_bus_message *m, void *u, sd_bus_error *e)
{
    sd_bus_message *reply = NULL;
    int r;

    (void)u; (void)e;
    r = sd_bus_message_new_method_return(m, &reply);
    if (r < 0) return r;
    r = sd_bus_message_open_container(reply, 'a', "o");
    if (r < 0) return r;
    r = sd_bus_message_append(reply, "o", DEVICE_PATH);
    if (r < 0) return r;
    r = sd_bus_message_close_container(reply);
    if (r < 0) return r;
    return sd_bus_send(NULL, reply, NULL);
}

/* --- Device ------------------------------------------------------------- */
static int method_claim(sd_bus_message *m, void *u, sd_bus_error *e)
{
    const char *who = NULL;
    int r;

    (void)u;
    r = sd_bus_message_read(m, "s", &who);
    if (r < 0) return r;

    /* An empty username means "whoever is calling". */
    if (!who || !*who) {
        sd_bus_creds *c = sd_bus_message_get_creds(m);
        uid_t uid;
        if (c && sd_bus_creds_get_euid(c, &uid) >= 0) {
            struct passwd *pw = getpwuid(uid);
            if (pw && pw->pw_name)
                who = pw->pw_name;
        }
    }
    if (!who || !*who)
        return sd_bus_error_set_const(e, "net.reactivated.Fprint.Error.Internal",
                                      "no username given and none could be derived");

    snprintf(claimed_user, sizeof claimed_user, "%s", who);
    syslog(LOG_INFO, "device claimed for '%s'", claimed_user);
    return sd_bus_reply_method_return(m, "");
}

static int method_release(sd_bus_message *m, void *u, sd_bus_error *e)
{
    (void)u; (void)e;
    stop_verify();
    claimed_user[0] = '\0';
    return sd_bus_reply_method_return(m, "");
}

static int method_verify_start(sd_bus_message *m, void *u, sd_bus_error *e)
{
    const char *finger = NULL;
    pid_t pid;
    int r;

    (void)u;
    r = sd_bus_message_read(m, "s", &finger);
    if (r < 0) return r;

    if (!claimed_user[0])
        return sd_bus_error_set_const(e, "net.reactivated.Fprint.Error.ClaimDevice",
                                      "device has not been claimed");
    if (verify_pid > 0)
        return sd_bus_error_set_const(e, "net.reactivated.Fprint.Error.AlreadyInUse",
                                      "a verification is already running");

    pid = fork();
    if (pid < 0)
        return sd_bus_error_set_errno(e, errno);

    if (pid == 0) {
        execl(SYNAFP_HELPER, "synafp-auth", claimed_user, (char *) NULL);
        _exit(2);
    }

    verify_pid = pid;
    r = sd_event_add_child(event, &verify_source, pid, WEXITED, on_verify_exit, NULL);
    if (r < 0) {
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
        verify_pid = 0;
        return sd_bus_error_set_errno(e, -r);
    }

    syslog(LOG_INFO, "verifying '%s' (finger '%s')", claimed_user,
           finger ? finger : "any");
    return sd_bus_reply_method_return(m, "");
}

static int method_verify_stop(sd_bus_message *m, void *u, sd_bus_error *e)
{
    (void)u; (void)e;
    stop_verify();
    return sd_bus_reply_method_return(m, "");
}

/* Some shells ask this before offering fingerprint at all. */
static int method_list_enrolled(sd_bus_message *m, void *u, sd_bus_error *e)
{
    const char *who = NULL;
    sd_bus_message *reply = NULL;
    syna_dev *d = NULL;
    syna_db_info_t info;
    int r, i, listed = 0;

    (void)u;
    r = sd_bus_message_read(m, "s", &who);
    if (r < 0) return r;

    r = sd_bus_message_new_method_return(m, &reply);
    if (r < 0) return r;
    r = sd_bus_message_open_container(reply, 'a', "s");
    if (r < 0) return r;

    /* Skip the device entirely while a scan is in flight. */
    if (verify_pid == 0 && syna_open(&d, NULL, 0) == SYNA_OK) {
        uint16_t storage = 0, userid = 0;
        syna_user_info ui;

        if (syna_db_info(d, &info) == SYNA_OK &&
            syna_db_user_storage(d, "StgWindsor", &storage) == SYNA_OK &&
            syna_lookup_user_by_name(d, storage, who, &userid) == SYNA_OK &&
            syna_db_get_user(d, userid, &ui) == SYNA_OK) {
            for (i = 0; i < ui.n_fingers; i++) {
                sd_bus_message_append(reply, "s",
                                      syna_subtype_name(ui.fingers[i].subtype));
                listed++;
            }
        }
        syna_close(d);
    }
    syslog(LOG_DEBUG, "ListEnrolledFingers('%s') -> %d", who ? who : "", listed);

    r = sd_bus_message_close_container(reply);
    if (r < 0) return r;
    return sd_bus_send(NULL, reply, NULL);
}

static const sd_bus_vtable manager_vtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_METHOD("GetDefaultDevice", "", "o", method_get_default_device,
                  SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("GetDevices", "", "ao", method_get_devices,
                  SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_VTABLE_END
};

static const sd_bus_vtable device_vtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_METHOD("Claim", "s", "", method_claim, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("Release", "", "", method_release, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("VerifyStart", "s", "", method_verify_start,
                  SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("VerifyStop", "", "", method_verify_stop,
                  SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("ListEnrolledFingers", "s", "as", method_list_enrolled,
                  SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_SIGNAL("VerifyStatus", "sb", 0),
    SD_BUS_VTABLE_END
};

int main(void)
{
    int r;

    openlog("synafp-fprintd", LOG_PID, LOG_AUTH);

    r = sd_event_default(&event);
    if (r < 0) { syslog(LOG_ERR, "sd_event_default: %s", strerror(-r)); return 1; }

    /* Child exits are delivered through the event loop, so block SIGCHLD. */
    sigset_t ss;
    sigemptyset(&ss);
    sigaddset(&ss, SIGCHLD);
    sigprocmask(SIG_BLOCK, &ss, NULL);

    r = sd_bus_open_system(&bus);
    if (r < 0) { syslog(LOG_ERR, "sd_bus_open_system: %s", strerror(-r)); return 1; }

    r = sd_bus_add_object_vtable(bus, NULL, MANAGER_PATH,
                                 "net.reactivated.Fprint.Manager",
                                 manager_vtable, NULL);
    if (r < 0) { syslog(LOG_ERR, "manager vtable: %s", strerror(-r)); return 1; }

    r = sd_bus_add_object_vtable(bus, NULL, DEVICE_PATH, DEVICE_IFACE,
                                 device_vtable, NULL);
    if (r < 0) { syslog(LOG_ERR, "device vtable: %s", strerror(-r)); return 1; }

    r = sd_bus_request_name(bus, "net.reactivated.Fprint", 0);
    if (r < 0) {
        syslog(LOG_ERR, "cannot take net.reactivated.Fprint: %s. "
                        "Is fprintd or open-fprintd running?", strerror(-r));
        return 1;
    }

    r = sd_bus_attach_event(bus, event, 0);
    if (r < 0) { syslog(LOG_ERR, "sd_bus_attach_event: %s", strerror(-r)); return 1; }

    syslog(LOG_INFO, "ready on net.reactivated.Fprint");
    r = sd_event_loop(event);
    if (r < 0)
        syslog(LOG_ERR, "event loop: %s", strerror(-r));

    stop_verify();
    sd_bus_unref(bus);
    sd_event_unref(event);
    closelog();
    return r < 0 ? 1 : 0;
}
