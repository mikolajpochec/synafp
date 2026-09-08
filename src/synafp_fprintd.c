/* synafp-fprintd - expose the sensor on the fprintd D-Bus interface.
 *
 * Screen lockers and desktop shells do not talk to PAM to light the reader.
 * They talk to fprintd: a locker calls VerifyStart when the lock screen
 * appears, so the sensor is armed and waiting before the user types anything.
 * A PAM module cannot do that, because PAM only runs once the user submits
 * input - which is why fingerprint-through-PAM only ever wakes the reader
 * after a password has been typed.
 *
 * This implements the subset of net.reactivated.Fprint that desktop shells
 * and screen lockers use:
 *   - VerifyStart/Stop for lock-screen authentication
 *   - EnrollStart/Stop for the Settings fingerprint panel
 *   - DeleteEnrolledFingers for removing prints
 *   - ListEnrolledFingers for listing what's stored
 *
 * Verification runs synafp-auth; enrollment runs synafp-enroll-helper.
 * Both are short-lived child processes that can be cancelled by SIGTERM.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include <errno.h>
#include <fcntl.h>
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

#ifndef SYNAFP_ENROLL_HELPER
#define SYNAFP_ENROLL_HELPER "/usr/local/libexec/synafp-enroll-helper"
#endif

#define MANAGER_PATH "/net/reactivated/Fprint/Manager"
#define DEVICE_PATH  "/net/reactivated/Fprint/Device/0"
#define DEVICE_IFACE "net.reactivated.Fprint.Device"

static sd_bus       *bus;
static sd_event     *event;
static char          claimed_user[256];

/* --- verify state -------------------------------------------------------- */
static pid_t         verify_pid;
static sd_event_source *verify_source;

/* --- enroll state -------------------------------------------------------- */
static pid_t         enroll_pid;
static sd_event_source *enroll_exit_source;
static sd_event_source *enroll_pipe_source;
static int           enroll_pipe_fd = -1;
static char          enroll_buf[1024];
static size_t        enroll_buf_len;

static void emit_verify_status(const char *result, int done)
{
    syslog(LOG_DEBUG, "VerifyStatus %s done=%d", result, done);
    sd_bus_emit_signal(bus, DEVICE_PATH, DEVICE_IFACE, "VerifyStatus",
                       "sb", result, done);
}

static void emit_enroll_status(const char *status, int done)
{
    syslog(LOG_DEBUG, "EnrollStatus %s done=%d", status, done);
    sd_bus_emit_signal(bus, DEVICE_PATH, DEVICE_IFACE, "EnrollStatus",
                       "sb", status, (int)done);
}

/* The helper's exit status, translated into fprintd's vocabulary. */
static const char *verify_result_for_exit(int code)
{
    switch (code) {
    case 0:  return "verify-match";
    case 1:  return "verify-no-match";
    default: return "verify-unknown-error";
    }
}

static int on_verify_exit(sd_event_source *s, const siginfo_t *si, void *userdata)
{
    int code = (si->si_code == CLD_EXITED) ? si->si_status : 2;

    (void)s; (void)userdata;
    verify_pid = 0;
    verify_source = sd_event_source_unref(verify_source);

    emit_verify_status(verify_result_for_exit(code), 1);
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

/* --- enroll helpers ------------------------------------------------------ */
static void process_enroll_line(const char *line)
{
    char status[64];
    int stage = 0;

    if (sscanf(line, "%63s %d", status, &stage) < 1)
        return;

    /* Translate helper status into fprintd status strings.
     *
     * GNOME Settings tracks enrollment by counting enroll-stage-passed
     * signals against num-enroll-stages.  After each stage-passed, it
     * shows a 750ms success tick then resets to the "place your finger"
     * prompt via a timeout.  We must NOT emit enroll-compare-scan between
     * stages because it cancels that timeout and hides the prompt.
     *
     * Mapping:
     *   enroll-finger-present → (suppressed, timeout handles prompt)
     *   enroll-compare-scan   → enroll-stage-passed  (touch accepted)
     *   enroll-finger-duplicate → enroll-retry-scan  (bad touch)
     *   enroll-result 1       → enroll-completed     (done=true)
     *   enroll-result 0       → enroll-failed        (done=true)
     */
    if (!strcmp(status, "enroll-compare-scan"))
        emit_enroll_status("enroll-stage-passed", 0);
    else if (!strcmp(status, "enroll-finger-duplicate"))
        emit_enroll_status("enroll-retry-scan", 0);
    else if (!strcmp(status, "enroll-result"))
        emit_enroll_status(stage ? "enroll-completed" : "enroll-failed", 1);
}

static int on_enroll_pipe_ready(sd_event_source *s, int fd, uint32_t revents, void *userdata)
{
    (void)s; (void)userdata;

    if (!(revents & EPOLLIN))
        return 0;

    ssize_t n = read(fd, enroll_buf + enroll_buf_len,
                     sizeof enroll_buf - enroll_buf_len - 1);
    if (n <= 0) {
        if (n == 0) {
            /* EOF: child closed its stdout. */
            sd_event_source_set_enabled(enroll_pipe_source, SD_EVENT_OFF);
        }
        return 0;
    }

    enroll_buf_len += n;
    enroll_buf[enroll_buf_len] = '\0';

    /* Process complete lines. */
    char *nl;
    while ((nl = memchr(enroll_buf, '\n', enroll_buf_len)) != NULL) {
        *nl = '\0';
        process_enroll_line(enroll_buf);
        size_t consumed = (size_t)(nl - enroll_buf) + 1;
        memmove(enroll_buf, nl + 1, enroll_buf_len - consumed);
        enroll_buf_len -= consumed;
    }

    return 0;
}

static int on_enroll_exit(sd_event_source *s, const siginfo_t *si, void *userdata)
{
    int code = (si->si_code == CLD_EXITED) ? si->si_status : 2;

    (void)s; (void)userdata;
    enroll_pid = 0;
    enroll_exit_source = sd_event_source_unref(enroll_exit_source);

    /* Flush any remaining partial line. */
    if (enroll_buf_len > 0) {
        enroll_buf[enroll_buf_len] = '\0';
        process_enroll_line(enroll_buf);
        enroll_buf_len = 0;
    }

    /* Drain the pipe to get any remaining data. */
    if (enroll_pipe_fd >= 0) {
        char tmp[256];
        while (read(enroll_pipe_fd, tmp, sizeof tmp) > 0)
            ;
    }

    /* Emit final status. */
    emit_enroll_status(code == 0 ? "enroll-completed" : "enroll-failed", 1);

    return 0;
}

static void stop_enroll(void)
{
    if (enroll_pid > 0) {
        kill(enroll_pid, SIGTERM);
        waitpid(enroll_pid, NULL, 0);
        enroll_pid = 0;
    }
    enroll_exit_source = sd_event_source_unref(enroll_exit_source);
    enroll_pipe_source = sd_event_source_unref(enroll_pipe_source);
    if (enroll_pipe_fd >= 0) {
        close(enroll_pipe_fd);
        enroll_pipe_fd = -1;
    }
    enroll_buf_len = 0;
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

    /* Lockers claim with an empty username, meaning "whoever is calling". */
    if (!who || !*who) {
        sd_bus_creds *c = NULL;
        uid_t uid;

        if (sd_bus_query_sender_creds(m, SD_BUS_CREDS_EUID, &c) >= 0) {
            if (sd_bus_creds_get_euid(c, &uid) >= 0) {
                struct passwd *pw = getpwuid(uid);
                if (pw && pw->pw_name) {
                    who = pw->pw_name;
                    syslog(LOG_INFO, "claim with no username, using caller '%s'", who);
                }
            }
            sd_bus_creds_unref(c);
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
    stop_enroll();
    claimed_user[0] = '\0';
    return sd_bus_reply_method_return(m, "");
}

/* --- Verify ------------------------------------------------------------- */
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
    if (verify_pid > 0 || enroll_pid > 0)
        return sd_bus_error_set_const(e, "net.reactivated.Fprint.Error.AlreadyInUse",
                                      "device is busy");

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

/* --- Enroll ------------------------------------------------------------- */
static int method_enroll_start(sd_bus_message *m, void *u, sd_bus_error *e)
{
    const char *finger = NULL;
    int pipefd[2] = { -1, -1 };
    pid_t pid;
    int r;

    (void)u;
    r = sd_bus_message_read(m, "s", &finger);
    if (r < 0) return r;

    if (!claimed_user[0])
        return sd_bus_error_set_const(e, "net.reactivated.Fprint.Error.ClaimDevice",
                                      "device has not been claimed");
    if (verify_pid > 0 || enroll_pid > 0)
        return sd_bus_error_set_const(e, "net.reactivated.Fprint.Error.AlreadyInUse",
                                      "device is busy");
    if (!finger || !*finger)
        return sd_bus_error_set_const(e, "net.reactivated.Fprint.Error.InvalidFinger",
                                      "no finger name given");

    if (pipe(pipefd) < 0)
        return sd_bus_error_set_errno(e, errno);

    pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return sd_bus_error_set_errno(e, errno);
    }

    if (pid == 0) {
        /* Child: close read end, exec helper with pipe as stdout. */
        close(pipefd[0]);
        if (pipefd[1] != 1) {
            dup2(pipefd[1], 1);
            close(pipefd[1]);
        }
        execl(SYNAFP_ENROLL_HELPER, "synafp-enroll-helper",
              claimed_user, finger, (char *) NULL);
        _exit(2);
    }

    /* Parent: close write end, set up pipe reading. */
    close(pipefd[1]);
    enroll_pipe_fd = pipefd[0];

    /* Set pipe non-blocking for the event loop. */
    int flags = fcntl(enroll_pipe_fd, F_GETFL, 0);
    fcntl(enroll_pipe_fd, F_SETFL, flags | O_NONBLOCK);

    enroll_pid = pid;
    enroll_buf_len = 0;

    r = sd_event_add_child(event, &enroll_exit_source, pid, WEXITED,
                           on_enroll_exit, NULL);
    if (r < 0) {
        stop_enroll();
        return sd_bus_error_set_errno(e, -r);
    }

    r = sd_event_add_io(event, &enroll_pipe_source, enroll_pipe_fd, EPOLLIN,
                        on_enroll_pipe_ready, NULL);
    if (r < 0) {
        stop_enroll();
        return sd_bus_error_set_errno(e, -r);
    }

    syslog(LOG_INFO, "enrolling '%s' finger '%s'", claimed_user, finger);
    return sd_bus_reply_method_return(m, "");
}

static int method_enroll_stop(sd_bus_message *m, void *u, sd_bus_error *e)
{
    (void)u; (void)e;
    stop_enroll();
    return sd_bus_reply_method_return(m, "");
}

/* --- Delete ------------------------------------------------------------- */
static int method_delete_fingers(sd_bus_message *m, void *u, sd_bus_error *e)
{
    const char *who = NULL;
    syna_dev *d = NULL;
    int r, removed = 0;

    (void)u;
    r = sd_bus_message_read(m, "s", &who);
    if (r < 0) return r;

    if (!who || !*who)
        return sd_bus_error_set_const(e, "net.reactivated.Fprint.Error.Internal",
                                      "no username given");

    if (verify_pid > 0 || enroll_pid > 0)
        return sd_bus_error_set_const(e, "net.reactivated.Fprint.Error.AlreadyInUse",
                                      "device is busy");

    r = syna_open(&d, NULL, 0);
    if (r != SYNA_OK)
        return sd_bus_error_set_const(e, "net.reactivated.Fprint.Error.Internal",
                                      "cannot open sensor");

    /* Delete all fingers (subtype < 0). */
    r = syna_delete(d, who, -1, &removed);
    syna_close(d);

    if (r != SYNA_OK && r != SYNA_ERR_NOT_FOUND)
        return sd_bus_error_set_const(e, "net.reactivated.Fprint.Error.Internal",
                                      "deletion failed");

    syslog(LOG_INFO, "deleted %d finger(s) for '%s'", removed, who);
    return sd_bus_reply_method_return(m, "");
}

/* --- List --------------------------------------------------------------- */
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
    if (verify_pid == 0 && enroll_pid == 0 &&
        syna_open(&d, NULL, 0) == SYNA_OK) {
        uint16_t storage = 0, userid = 0;
        syna_user_info ui;

        if (syna_db_info(d, &info) == SYNA_OK &&
            syna_db_user_storage(d, "StgWindsor", &storage) == SYNA_OK &&
            syna_lookup_user_by_name(d, storage, who, &userid) == SYNA_OK &&
            syna_db_get_user(d, userid, &ui) == SYNA_OK) {
            for (i = 0; i < ui.n_fingers; i++) {
                sd_bus_message_append(reply, "s",
                                      syna_subtype_fprintd_name(ui.fingers[i].subtype));
                listed++;
            }
        }
        syna_close(d);
    }
    syslog(LOG_INFO, "ListEnrolledFingers('%s') -> %d finger(s)", who ? who : "", listed);

    r = sd_bus_message_close_container(reply);
    if (r < 0) return r;
    return sd_bus_send(NULL, reply, NULL);
}

/* --- vtables ------------------------------------------------------------ */
static const sd_bus_vtable manager_vtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_METHOD("GetDefaultDevice", "", "o", method_get_default_device,
                  SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("GetDevices", "", "ao", method_get_devices,
                  SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_VTABLE_END
};

/* fprintd names its properties with hyphens - scan-type, num-enroll-stages -
 * which D-Bus does not allow in member names and sd-bus refuses to put in a
 * vtable. fprintd itself uses GDBus, which does not enforce that. So serve the
 * Properties interface by hand, where the name is only ever a string argument.
 */
static int append_prop(sd_bus_message *reply, const char *prop)
{
    if (!strcmp(prop, "name"))
        return sd_bus_message_append(reply, "v", "s", "synafp");
    if (!strcmp(prop, "scan-type"))
        return sd_bus_message_append(reply, "v", "s", "press");
    if (!strcmp(prop, "num-enroll-stages"))
        return sd_bus_message_append(reply, "v", "i", 5);
    if (!strcmp(prop, "finger-present"))
        return sd_bus_message_append(reply, "v", "b", 0);
    if (!strcmp(prop, "finger-needed"))
        return sd_bus_message_append(reply, "v", "b",
                                     verify_pid > 0 || enroll_pid > 0);
    return -ENOENT;
}

static const char *const device_props[] = {
    "name", "scan-type", "num-enroll-stages", "finger-present", "finger-needed"
};

static int device_properties(sd_bus_message *m, void *u, sd_bus_error *e)
{
    const char *iface = NULL, *prop = NULL;
    sd_bus_message *reply = NULL;
    size_t i;
    int r;

    (void)u;

    if (sd_bus_message_is_method_call(m, "org.freedesktop.DBus.Properties", "Get")) {
        r = sd_bus_message_read(m, "ss", &iface, &prop);
        if (r < 0) return r;

        r = sd_bus_message_new_method_return(m, &reply);
        if (r < 0) return r;
        r = append_prop(reply, prop);
        if (r < 0)
            return sd_bus_error_setf(e, SD_BUS_ERROR_UNKNOWN_PROPERTY,
                                     "no such property %s", prop);
        return sd_bus_send(NULL, reply, NULL);
    }

    if (sd_bus_message_is_method_call(m, "org.freedesktop.DBus.Properties", "GetAll")) {
        r = sd_bus_message_new_method_return(m, &reply);
        if (r < 0) return r;
        r = sd_bus_message_open_container(reply, 'a', "{sv}");
        if (r < 0) return r;
        for (i = 0; i < sizeof device_props / sizeof device_props[0]; i++) {
            r = sd_bus_message_open_container(reply, 'e', "sv");
            if (r < 0) return r;
            r = sd_bus_message_append(reply, "s", device_props[i]);
            if (r < 0) return r;
            r = append_prop(reply, device_props[i]);
            if (r < 0) return r;
            r = sd_bus_message_close_container(reply);
            if (r < 0) return r;
        }
        r = sd_bus_message_close_container(reply);
        if (r < 0) return r;
        return sd_bus_send(NULL, reply, NULL);
    }

    return 0;   /* not ours: let the vtable handle it */
}

static const sd_bus_vtable device_vtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_METHOD("Claim", "s", "", method_claim, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("Release", "", "", method_release, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("VerifyStart", "s", "", method_verify_start,
                  SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("VerifyStop", "", "", method_verify_stop,
                  SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("EnrollStart", "s", "", method_enroll_start,
                  SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("EnrollStop", "", "", method_enroll_stop,
                  SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("DeleteEnrolledFingers", "s", "", method_delete_fingers,
                  SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("ListEnrolledFingers", "s", "as", method_list_enrolled,
                  SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_SIGNAL("VerifyStatus", "sb", 0),
    SD_BUS_SIGNAL("EnrollStatus", "sb", 0),
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

    /* Have the bus attach the sender's uid to incoming messages. */
    r = sd_bus_negotiate_creds(bus, 1, SD_BUS_CREDS_EUID | SD_BUS_CREDS_PID);
    if (r < 0)
        syslog(LOG_WARNING, "could not negotiate creds: %s", strerror(-r));

    r = sd_bus_add_object_vtable(bus, NULL, MANAGER_PATH,
                                 "net.reactivated.Fprint.Manager",
                                 manager_vtable, NULL);
    if (r < 0) { syslog(LOG_ERR, "manager vtable: %s", strerror(-r)); return 1; }

    r = sd_bus_add_object_vtable(bus, NULL, DEVICE_PATH, DEVICE_IFACE,
                                 device_vtable, NULL);
    if (r < 0) { syslog(LOG_ERR, "device vtable: %s", strerror(-r)); return 1; }

    /* Properties are a convenience for clients that ask; never a reason to
     * refuse to start. */
    r = sd_bus_add_object(bus, NULL, DEVICE_PATH, device_properties, NULL);
    if (r < 0)
        syslog(LOG_WARNING, "device properties unavailable: %s", strerror(-r));

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
    stop_enroll();
    sd_bus_unref(bus);
    sd_event_unref(event);
    closelog();
    return r < 0 ? 1 : 0;
}
