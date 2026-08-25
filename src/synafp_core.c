/* synafp_core.c - USB transport, device discovery and session lifecycle.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include "synafp_priv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>

int syna_debug_level = 0;

void syna_set_debug(int level) { syna_debug_level = level; }

void syna_dbg(const char *fmt, ...)
{
    va_list ap;
    if (syna_debug_level <= 0) return;
    fputs("synafp: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

void syna_hexdump(const char *tag, const uint8_t *b, int n)
{
    int i, limit = n;

    if (syna_debug_level < 2) return;
    if (syna_debug_level < 3 && limit > 128) limit = 128;

    fprintf(stderr, "synafp: %s [%d]:", tag, n);
    for (i = 0; i < limit; i++) {
        if ((i % 16) == 0) fprintf(stderr, "\n synafp:   ");
        fprintf(stderr, " %02x", b[i]);
    }
    if (limit < n) fprintf(stderr, " ... (%d more)", n - limit);
    fputc('\n', stderr);
}

const char *syna_strerror(int rc)
{
    static char buf[128];

    if (SYNA_IS_SENSOR_ERR(rc)) {
        int st = SYNA_SENSOR_STATUS(rc);
        const char *s = NULL;
        switch (st) {
        case 0x0401: s = "command not supported by this firmware"; break;
        case 0x0403: s = "command not allowed outside a secure session"; break;
        case 0x0491: s = "nothing to commit"; break;
        case 0x04b0: s = "no firmware extension loaded"; break;
        case 0x04b3: s = "no such record"; break;
        }
        if (s)
            snprintf(buf, sizeof buf, "%s (sensor status 0x%04x)", s, st);
        else
            snprintf(buf, sizeof buf, "sensor reported status 0x%04x", st);
        return buf;
    }

    switch (rc) {
    case SYNA_OK:              return "success";
    case SYNA_ERR_USB:         return "USB transfer failed";
    case SYNA_ERR_NO_DEVICE:   return "no supported fingerprint sensor found";
    case SYNA_ERR_PROTO:       return "protocol error";
    case SYNA_ERR_TIMEOUT:     return "operation timed out";
    case SYNA_ERR_CANCELLED:   return "operation cancelled";
    case SYNA_ERR_NOMEM:       return "out of memory";
    case SYNA_ERR_INVAL:       return "invalid argument";
    case SYNA_ERR_ACCESS:      return "permission denied";
    case SYNA_ERR_BUSY:        return "sensor is claimed by another process "
                                      "(stop python3-validity / open-fprintd / fprintd)";
    case SYNA_ERR_UNSUPPORTED: return "operation not supported by this sensor";
    case SYNA_ERR_PAIRING:     return "sensor is paired to a different computer";
    case SYNA_ERR_NOT_FOUND:   return "no such record on the sensor";
    }
    snprintf(buf, sizeof buf, "unknown error %d", rc);
    return buf;
}

int syna_usb_error(int e)
{
    switch (e) {
    case LIBUSB_ERROR_TIMEOUT:       return SYNA_ERR_TIMEOUT;
    case LIBUSB_ERROR_ACCESS:        return SYNA_ERR_ACCESS;
    case LIBUSB_ERROR_NO_DEVICE:     return SYNA_ERR_NO_DEVICE;
    case LIBUSB_ERROR_NOT_FOUND:     return SYNA_ERR_NO_DEVICE;
    case LIBUSB_ERROR_BUSY:          return SYNA_ERR_BUSY;
    case LIBUSB_ERROR_NOT_SUPPORTED: return SYNA_ERR_UNSUPPORTED;
    default:                         return SYNA_ERR_USB;
    }
}

/* --------------------------------------------------------------------------
 * Discovery
 *
 * Match on the endpoint signature rather than a product-ID table, so new
 * models of the same family work without a code change.
 * ----------------------------------------------------------------------- */
static int vendor_supported(uint16_t vid)
{
    return vid == SYNA_VENDOR_SYNAPTICS || vid == SYNA_VENDOR_VALIDITY;
}

static int find_interface(libusb_device *dev)
{
    struct libusb_config_descriptor *cfg = NULL;
    int num = -1, i, j, k;

    if (libusb_get_active_config_descriptor(dev, &cfg) != 0 || !cfg)
        return -1;

    for (i = 0; i < cfg->bNumInterfaces && num < 0; i++) {
        const struct libusb_interface *itf = &cfg->interface[i];
        for (j = 0; j < itf->num_altsetting && num < 0; j++) {
            const struct libusb_interface_descriptor *id = &itf->altsetting[j];
            int have_req = 0, have_rep = 0;

            if (id->bInterfaceClass != LIBUSB_CLASS_VENDOR_SPEC)
                continue;
            for (k = 0; k < id->bNumEndpoints; k++) {
                uint8_t a = id->endpoint[k].bEndpointAddress;
                uint8_t t = id->endpoint[k].bmAttributes & LIBUSB_TRANSFER_TYPE_MASK;
                if (a == SYNA_EP_REQUEST && t == LIBUSB_TRANSFER_TYPE_BULK) have_req = 1;
                if (a == SYNA_EP_REPLY   && t == LIBUSB_TRANSFER_TYPE_BULK) have_rep = 1;
            }
            if (have_req && have_rep)
                num = id->bInterfaceNumber;
        }
    }
    libusb_free_config_descriptor(cfg);
    return num;
}

static void read_serial(syna_dev *d)
{
    struct libusb_device_descriptor dd;
    unsigned char tmp[64];
    int n;

    d->serial[0] = '\0';
    if (libusb_get_device_descriptor(libusb_get_device(d->h), &dd) != 0)
        return;
    if (!dd.iSerialNumber)
        return;
    n = libusb_get_string_descriptor_ascii(d->h, dd.iSerialNumber, tmp, sizeof tmp - 1);
    if (n > 0) {
        if (n > (int)sizeof d->serial - 1) n = (int)sizeof d->serial - 1;
        memcpy(d->serial, tmp, (size_t)n);
        d->serial[n] = '\0';
    }
}

static int usb_bring_up(syna_dev *d, const char *want_serial)
{
    libusb_device **list = NULL;
    ssize_t cnt, i;
    int rc = SYNA_ERR_NO_DEVICE;

    cnt = libusb_get_device_list(d->ctx, &list);
    if (cnt < 0)
        return syna_usb_error((int)cnt);

    for (i = 0; i < cnt; i++) {
        struct libusb_device_descriptor dd;
        libusb_device_handle *h = NULL;
        int e, ifnum;

        if (libusb_get_device_descriptor(list[i], &dd) != 0)
            continue;
        if (!vendor_supported(dd.idVendor))
            continue;
        if (dd.bDeviceClass != LIBUSB_CLASS_VENDOR_SPEC)
            continue;

        ifnum = find_interface(list[i]);
        if (ifnum < 0)
            continue;

        e = libusb_open(list[i], &h);
        if (e != 0) {
            syna_dbg("cannot open %04x:%04x: %s", dd.idVendor, dd.idProduct,
                     libusb_strerror(e));
            if (rc == SYNA_ERR_NO_DEVICE)
                rc = syna_usb_error(e);
            continue;
        }

        d->h = h;
        d->vid = dd.idVendor;
        d->pid = dd.idProduct;
        d->ifnum = ifnum;
        read_serial(d);

        if (want_serial && *want_serial && strcmp(want_serial, d->serial) != 0) {
            libusb_close(h);
            d->h = NULL;
            continue;
        }

        libusb_set_auto_detach_kernel_driver(h, 1);
        e = libusb_claim_interface(h, ifnum);
        if (e != 0) {
            syna_dbg("claim_interface(%d): %s", ifnum, libusb_strerror(e));
            libusb_close(h);
            d->h = NULL;
            rc = syna_usb_error(e);
            continue;
        }

        syna_dbg("opened %04x:%04x serial=%s interface=%d",
                 dd.idVendor, dd.idProduct, d->serial, ifnum);
        rc = SYNA_OK;
        break;
    }

    libusb_free_device_list(list, 1);
    return rc;
}

static void usb_tear_down(syna_dev *d)
{
    if (d->h) {
        libusb_release_interface(d->h, d->ifnum);
        libusb_close(d->h);
        d->h = NULL;
    }
}

static int usb_reset_and_reopen(syna_dev *d, const char *want_serial)
{
    int e;

    if (!d->h)
        return usb_bring_up(d, want_serial);

    e = libusb_reset_device(d->h);
    if (e == 0) {
        libusb_claim_interface(d->h, d->ifnum);
        return SYNA_OK;
    }

    syna_dbg("reset needs re-enumeration (%s), reopening", libusb_strerror(e));
    usb_tear_down(d);
    for (e = 0; e < 40; e++) {
        struct timespec ts = { 0, 100 * 1000 * 1000 };
        nanosleep(&ts, NULL);
        if (usb_bring_up(d, want_serial) == SYNA_OK)
            return SYNA_OK;
    }
    return SYNA_ERR_NO_DEVICE;
}

/* --------------------------------------------------------------------------
 * Raw transfers
 * ----------------------------------------------------------------------- */
int syna_bulk_out(syna_dev *d, const uint8_t *buf, int len, unsigned timeout_ms)
{
    int transferred = 0, e;

    syna_hexdump("OUT", buf, len);
    e = libusb_bulk_transfer(d->h, SYNA_EP_REQUEST, (unsigned char *)buf,
                             len, &transferred, timeout_ms);
    if (e != 0) {
        syna_dbg("bulk out failed: %s", libusb_strerror(e));
        return syna_usb_error(e);
    }
    if (transferred != len)
        return SYNA_ERR_PROTO;
    return SYNA_OK;
}

int syna_bulk_in(syna_dev *d, uint8_t *buf, int cap, int *out_len, unsigned timeout_ms)
{
    int transferred = 0, e;

    e = libusb_bulk_transfer(d->h, SYNA_EP_REPLY, buf, cap, &transferred, timeout_ms);
    if (e != 0) {
        syna_dbg("bulk in failed: %s", libusb_strerror(e));
        return syna_usb_error(e);
    }
    *out_len = transferred;
    syna_hexdump("IN", buf, transferred);
    return SYNA_OK;
}

/* --------------------------------------------------------------------------
 * Firmware version - the one command that always works
 * ----------------------------------------------------------------------- */
static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

int syna_fw_version_get(syna_dev *d, syna_fw_version *out)
{
    uint8_t cmd = VCSFW_CMD_GET_VERSION;
    syna_buf reply = { 0 };
    int rc, attempt;

    if (!d || !d->h || !out)
        return SYNA_ERR_INVAL;

    for (attempt = 0; attempt < 2; attempt++) {
        rc = syna_vcsfw_call(d, &cmd, 1, &reply);
        if (rc != SYNA_OK) {
            /* The sensor often answers the very first poll with a stale error. */
            syna_dbg("version query attempt %d: %s", attempt + 1, syna_strerror(rc));
            continue;
        }
        if (reply.len < 28) {
            rc = SYNA_ERR_PROTO;
            continue;
        }

        out->build_time     = rd32(reply.p + 2);
        out->build_num      = rd32(reply.p + 6);
        out->version_major  = reply.p[10];
        out->version_minor  = reply.p[11];
        out->target         = reply.p[12];
        out->product        = reply.p[13];
        out->silicon_rev    = reply.p[14];
        out->formal_release = reply.p[15];
        out->platform       = reply.p[16];
        out->patch          = reply.p[17];
        memcpy(out->serial_number, reply.p + 18, 6);
        out->security       = (uint16_t)(reply.p[24] | (reply.p[25] << 8));
        out->iface          = reply.p[26];
        out->device_type    = reply.p[27];
        break;
    }

    syna_buf_free(&reply);
    return rc;
}

/* --------------------------------------------------------------------------
 * Open / close
 * ----------------------------------------------------------------------- */
static int establish_session(syna_dev *d)
{
    syna_buf flash = { 0 };
    int rc;

    rc = syna_tls_set_hwkey_from_dmi(&d->tls);
    if (rc != SYNA_OK)
        return rc;

    /* Partition 1 carries the TLS credentials and is readable without a
     * session, which is how the whole thing bootstraps. */
    rc = syna_read_flash(d, SYNA_TLS_PARTITION, 0, SYNA_TLS_FLASH_SIZE, &flash);
    if (rc != SYNA_OK) {
        syna_dbg("cannot read TLS partition: %s", syna_strerror(rc));
        goto done;
    }
    syna_dbg("read %zu bytes of TLS flash", flash.len);

    rc = syna_tls_parse_flash(&d->tls, flash.p, flash.len);
    if (rc != SYNA_OK)
        goto done;

    rc = syna_tls_open(d);
done:
    syna_buf_free(&flash);
    return rc;
}

int syna_open(syna_dev **out, const char *serial, unsigned flags)
{
    syna_dev *d;
    int rc;

    if (!out)
        return SYNA_ERR_INVAL;
    *out = NULL;

    if (getenv("SYNAFP_DEBUG"))
        syna_debug_level = atoi(getenv("SYNAFP_DEBUG"));

    d = calloc(1, sizeof *d);
    if (!d)
        return SYNA_ERR_NOMEM;
    d->op_timeout_ms = 30000;
    d->rx = malloc(SYNA_RX_BUFFER);
    if (!d->rx) {
        free(d);
        return SYNA_ERR_NOMEM;
    }

    rc = libusb_init(&d->ctx);
    if (rc != 0) {
        free(d->rx);
        free(d);
        return syna_usb_error(rc);
    }

    rc = usb_bring_up(d, serial);
    if (rc != SYNA_OK)
        goto fail;

    if (flags & SYNA_OPEN_RESET) {
        rc = usb_reset_and_reopen(d, serial);
        if (rc != SYNA_OK)
            goto fail;
    }

    rc = syna_fw_version_get(d, &d->fw);
    if (rc != SYNA_OK && !(flags & SYNA_OPEN_RESET)) {
        syna_dbg("probe failed (%s), resetting", syna_strerror(rc));
        if (usb_reset_and_reopen(d, serial) == SYNA_OK)
            rc = syna_fw_version_get(d, &d->fw);
    }
    if (rc != SYNA_OK)
        goto fail;

    syna_dbg("firmware %u.%u build %u, security 0x%04x",
             d->fw.version_major, d->fw.version_minor, d->fw.build_num, d->fw.security);

    /* Must happen before the handshake: an uninitialised sensor accepts the
     * TLS session but crashes on the first capture program. */
    rc = syna_send_init(d);
    if (rc != SYNA_OK) {
        syna_dbg("initialisation failed: %s", syna_strerror(rc));
        goto fail;
    }

    if (!(flags & SYNA_OPEN_NO_TLS)) {
        rc = establish_session(d);
        if (rc != SYNA_OK)
            goto fail;
    }

    *out = d;
    return SYNA_OK;

fail:
    syna_tls_free(&d->tls);
    usb_tear_down(d);
    if (d->ctx)
        libusb_exit(d->ctx);
    free(d->rx);
    free(d);
    return rc;
}

int syna_set_timeout(syna_dev *d, unsigned ms)
{
    if (!d)
        return SYNA_ERR_INVAL;
    d->op_timeout_ms = ms;
    return SYNA_OK;
}

int syna_cancel(syna_dev *d)
{
    if (!d)
        return SYNA_ERR_INVAL;
    d->cancel_req = 1;
    return SYNA_OK;
}

void syna_close(syna_dev *d)
{
    if (!d)
        return;
    syna_buf_free(&d->factory_calib);
    syna_buf_free(&d->calib_data);
    syna_tls_free(&d->tls);
    usb_tear_down(d);
    if (d->ctx)
        libusb_exit(d->ctx);
    free(d->rx);
    free(d);
}

int syna_has_session(const syna_dev *d)
{
    return d && d->tls.secure_tx && d->tls.secure_rx;
}

const char *syna_model_name(const syna_dev *d)
{
    return (d && d->model_name) ? d->model_name : "unknown";
}

const char *syna_serial(const syna_dev *d) { return d ? d->serial : ""; }
uint16_t syna_product_id(const syna_dev *d) { return d ? d->pid : 0; }

/* --------------------------------------------------------------------------
 * Privilege separation
 *
 * Root is needed for exactly two things: reading the DMI serial that seeds
 * the session key, and claiming the USB device. Both happen in syna_open().
 * Everything afterwards - the TLS handshake, every parser fed by the sensor,
 * the capture program builder - can run unprivileged, and should, because a
 * memory-safety bug in any of it would otherwise be a root bug.
 *
 * Call this immediately after syna_open() in a program that does not need to
 * write host state. It is deliberately not called from the library itself,
 * and must never be used from a PAM module, which has to stay root.
 * ----------------------------------------------------------------------- */
int syna_drop_privileges(void)
{
    const char *s;
    uid_t uid;
    gid_t gid;

    if (geteuid() != 0)
        return SYNA_OK;                 /* nothing to drop */

    /* Prefer the account that invoked us through sudo; otherwise fall back to
     * nobody, so we still shed root even when run directly. */
    s = getenv("SUDO_UID");
    if (s && *s) {
        uid = (uid_t)strtoul(s, NULL, 10);
        s = getenv("SUDO_GID");
        gid = (s && *s) ? (gid_t)strtoul(s, NULL, 10) : (gid_t)uid;
    } else {
        struct passwd *pw = getpwnam("nobody");
        if (!pw) {
            syna_dbg("cannot drop privileges: no nobody account");
            return SYNA_ERR_ACCESS;
        }
        uid = pw->pw_uid;
        gid = pw->pw_gid;
    }

    if (uid == 0) {
        syna_dbg("refusing to 'drop' privileges to uid 0");
        return SYNA_ERR_ACCESS;
    }

    if (setgroups(0, NULL) != 0) {
        syna_dbg("setgroups failed");
        return SYNA_ERR_ACCESS;
    }
    if (setgid(gid) != 0 || setuid(uid) != 0) {
        syna_dbg("setgid/setuid failed");
        return SYNA_ERR_ACCESS;
    }

    /* If root can be regained the drop was worthless, so verify it. */
    if (setuid(0) == 0) {
        syna_dbg("privileges could be regained after dropping");
        return SYNA_ERR_ACCESS;
    }

    syna_dbg("dropped privileges to uid %u gid %u", (unsigned)uid, (unsigned)gid);
    return SYNA_OK;
}
