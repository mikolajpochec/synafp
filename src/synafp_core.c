/* synafp_core.c - USB transport, BMKT framing and the command engine.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#define _POSIX_C_SOURCE 200809L
#include "synafp_priv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

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
    int i;
    if (syna_debug_level < 2) return;
    fprintf(stderr, "synafp: %s [%d]:", tag, n);
    for (i = 0; i < n; i++) {
        if ((i % 16) == 0) fprintf(stderr, "\n synafp:   ");
        fprintf(stderr, " %02x", b[i]);
    }
    fputc('\n', stderr);
}

static uint64_t now_ms(void)
{
    struct timespec ts;
#ifdef CLOCK_MONOTONIC
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
        return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
#endif
    return (uint64_t)time(NULL) * 1000u;
}

const char *syna_strerror(int rc)
{
    static char buf[128];

    if (SYNA_IS_SENSOR_ERR(rc)) {
        int st = SYNA_SENSOR_STATUS(rc);
        const char *s = NULL;
        switch (st) {
        case BMKT_STATUS_NOT_INITIALIZED:  s = "fingerprint system not initialized"; break;
        case BMKT_STATUS_BUSY:             s = "sensor busy with another operation"; break;
        case BMKT_STATUS_OPERATION_DENIED: s = "operation denied by sensor"; break;
        case BMKT_STATUS_CORRUPT_MESSAGE:  s = "sensor received a corrupt message"; break;
        case BMKT_STATUS_INVALID_PARAM:    s = "invalid parameter"; break;
        case BMKT_STATUS_UNRECOGNIZED_MESSAGE: s = "command not recognized by this firmware"; break;
        case BMKT_STATUS_OP_TIME_OUT:      s = "sensor timed out waiting for a finger"; break;
        case BMKT_STATUS_GENERAL_ERROR:    s = "general sensor error"; break;
        case BMKT_STATUS_SENSOR_RESET:     s = "sensor was reset"; break;
        case BMKT_STATUS_SENSOR_MALFUNCTION: s = "sensor malfunction"; break;
        case BMKT_STATUS_SENSOR_TAMPERED:  s = "sensor reports tampering"; break;
        case BMKT_STATUS_SENSOR_NOT_INIT:  s = "sensor not initialized"; break;
        case BMKT_STATUS_STIMULUS_ERROR:   s = "bad finger placement, try again"; break;
        case BMKT_STATUS_CORRUPT_TEMPLATE: s = "stored template is corrupt"; break;
        case BMKT_STATUS_FEATURE_EXTRACT_FAIL: s = "could not extract features from image"; break;
        case BMKT_STATUS_ENROLL_FAIL:      s = "enrolment failed"; break;
        case BMKT_STATUS_ENROLLMENT_EXISTS: s = "this finger is already enrolled"; break;
        case BMKT_STATUS_INVALID_FP_IMAGE: s = "poor quality image"; break;
        case BMKT_STATUS_NO_MATCH:         s = "no match"; break;
        case BMKT_STATUS_DATABASE_FULL:    s = "sensor template storage is full"; break;
        case BMKT_STATUS_DATABASE_EMPTY:   s = "no fingerprints are enrolled"; break;
        case BMKT_STATUS_DATABASE_ACCESS_FAIL: s = "template storage access failed"; break;
        case BMKT_STATUS_NO_RECORD_EXISTS: s = "no such enrolled fingerprint"; break;
        case BMKT_STATUS_SPOOF_ALERT:      s = "anti-spoofing rejected the finger"; break;
        }
        if (s) {
            snprintf(buf, sizeof buf, "%s (sensor status %d)", s, st);
        } else {
            snprintf(buf, sizeof buf, "sensor reported status %d", st);
        }
        return buf;
    }

    switch (rc) {
    case SYNA_OK:              return "success";
    case SYNA_ERR_USB:         return "USB transfer failed";
    case SYNA_ERR_NO_DEVICE:   return "no supported Synaptics fingerprint sensor found";
    case SYNA_ERR_PROTO:       return "protocol error (malformed reply from sensor)";
    case SYNA_ERR_TIMEOUT:     return "operation timed out";
    case SYNA_ERR_CANCELLED:   return "operation cancelled";
    case SYNA_ERR_NOMEM:       return "out of memory";
    case SYNA_ERR_INVAL:       return "invalid argument";
    case SYNA_ERR_ACCESS:      return "permission denied opening the USB device";
    case SYNA_ERR_BUSY:        return "device is claimed by another process";
    case SYNA_ERR_UNSUPPORTED: return "operation not supported by this sensor";
    }
    snprintf(buf, sizeof buf, "unknown error %d", rc);
    return buf;
}

static int usb_err(int e)
{
    switch (e) {
    case LIBUSB_ERROR_TIMEOUT:      return SYNA_ERR_TIMEOUT;
    case LIBUSB_ERROR_ACCESS:       return SYNA_ERR_ACCESS;
    case LIBUSB_ERROR_NO_DEVICE:    return SYNA_ERR_NO_DEVICE;
    case LIBUSB_ERROR_NOT_FOUND:    return SYNA_ERR_NO_DEVICE;
    case LIBUSB_ERROR_BUSY:         return SYNA_ERR_BUSY;
    case LIBUSB_ERROR_NOT_SUPPORTED:return SYNA_ERR_UNSUPPORTED;
    default:                        return SYNA_ERR_USB;
    }
}

/* --------------------------------------------------------------------------
 * Device discovery
 *
 * Rather than hardcoding a product-ID table (which goes stale with every new
 * ThinkPad), we accept any Synaptics vendor-class device that exposes the
 * Prometheus endpoint layout: bulk OUT 0x01, bulk IN 0x81 and interrupt IN
 * 0x83. That is the signature of the BMKT command protocol.
 * ----------------------------------------------------------------------- */
static int device_looks_right(libusb_device *dev, struct libusb_device_descriptor *dd)
{
    struct libusb_config_descriptor *cfg = NULL;
    int ok = 0, i, j, k;

    if (dd->idVendor != SYNA_VENDOR_ID)
        return 0;
    if (dd->bDeviceClass != LIBUSB_CLASS_VENDOR_SPEC)
        return 0;
    if (libusb_get_active_config_descriptor(dev, &cfg) != 0 || !cfg)
        return 0;

    for (i = 0; i < cfg->bNumInterfaces && !ok; i++) {
        const struct libusb_interface *itf = &cfg->interface[i];
        for (j = 0; j < itf->num_altsetting && !ok; j++) {
            const struct libusb_interface_descriptor *id = &itf->altsetting[j];
            int have_req = 0, have_rep = 0, have_int = 0;
            if (id->bInterfaceClass != LIBUSB_CLASS_VENDOR_SPEC)
                continue;
            for (k = 0; k < id->bNumEndpoints; k++) {
                uint8_t a = id->endpoint[k].bEndpointAddress;
                uint8_t t = id->endpoint[k].bmAttributes & LIBUSB_TRANSFER_TYPE_MASK;
                if (a == SYNA_EP_REQUEST   && t == LIBUSB_TRANSFER_TYPE_BULK)      have_req = 1;
                if (a == SYNA_EP_REPLY     && t == LIBUSB_TRANSFER_TYPE_BULK)      have_rep = 1;
                if (a == SYNA_EP_INTERRUPT && t == LIBUSB_TRANSFER_TYPE_INTERRUPT) have_int = 1;
            }
            if (have_req && have_rep && have_int) {
                ok = 1;
            }
        }
    }
    libusb_free_config_descriptor(cfg);
    return ok;
}

static int find_interface_number(libusb_device *dev)
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
            for (k = 0; k < id->bNumEndpoints; k++) {
                uint8_t a = id->endpoint[k].bEndpointAddress;
                if (a == SYNA_EP_REQUEST) have_req = 1;
                if (a == SYNA_EP_REPLY)   have_rep = 1;
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

/* Open the USB device, claim the interface. Does not talk the protocol. */
static int usb_bring_up(syna_dev *d, const char *want_serial)
{
    libusb_device **list = NULL;
    ssize_t cnt, i;
    int rc = SYNA_ERR_NO_DEVICE;

    cnt = libusb_get_device_list(d->ctx, &list);
    if (cnt < 0)
        return usb_err((int)cnt);

    for (i = 0; i < cnt; i++) {
        struct libusb_device_descriptor dd;
        libusb_device_handle *h = NULL;
        int e, ifnum;

        if (libusb_get_device_descriptor(list[i], &dd) != 0)
            continue;
        if (!device_looks_right(list[i], &dd))
            continue;

        ifnum = find_interface_number(list[i]);
        if (ifnum < 0)
            continue;

        e = libusb_open(list[i], &h);
        if (e != 0) {
            syna_dbg("libusb_open failed for %04x:%04x: %s",
                     dd.idVendor, dd.idProduct, libusb_strerror(e));
            if (rc == SYNA_ERR_NO_DEVICE)
                rc = usb_err(e);
            continue;
        }

        d->h = h;
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
            syna_dbg("claim_interface(%d) failed: %s", ifnum, libusb_strerror(e));
            libusb_close(h);
            d->h = NULL;
            rc = usb_err(e);
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

/* A USB reset can force re-enumeration, which invalidates the handle. Handle
 * that by tearing everything down and searching again. */
static int usb_reset_and_reopen(syna_dev *d, const char *want_serial)
{
    int e;

    if (!d->h)
        return usb_bring_up(d, want_serial);

    e = libusb_reset_device(d->h);
    if (e == 0) {
        /* Interface claim survives a successful reset on Linux, but re-claim
         * defensively; ignore an EBUSY that means we still hold it. */
        libusb_claim_interface(d->h, d->ifnum);
        return SYNA_OK;
    }

    syna_dbg("reset requires re-enumeration (%s), reopening", libusb_strerror(e));
    usb_tear_down(d);
    /* Give the kernel a moment to re-enumerate the device. */
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
        return usb_err(e);
    }
    if (transferred != len) {
        syna_dbg("short bulk out: %d of %d", transferred, len);
        return SYNA_ERR_PROTO;
    }
    return SYNA_OK;
}

int syna_bulk_in(syna_dev *d, uint8_t *buf, int cap, int *out_len, unsigned timeout_ms)
{
    int transferred = 0, e;

    e = libusb_bulk_transfer(d->h, SYNA_EP_REPLY, buf, cap, &transferred, timeout_ms);
    if (e != 0) {
        syna_dbg("bulk in failed: %s", libusb_strerror(e));
        return usb_err(e);
    }
    *out_len = transferred;
    syna_hexdump("IN", buf, transferred);
    return SYNA_OK;
}

/* Send a bare firmware-level command (no BMKT payload). */
int syna_fw_cmd(syna_dev *d, uint8_t cmd)
{
    return syna_bulk_out(d, &cmd, 1, SYNA_CMD_TIMEOUT_MS);
}

/* Wrap a BMKT message in an ACE firmware command and send it. */
int syna_send_bmkt(syna_dev *d, uint8_t seq, uint8_t msg_id,
                   const uint8_t *payload, int payload_len)
{
    uint8_t buf[1 + BMKT_HEADER_LEN + BMKT_MAX_PAYLOAD];

    if (payload_len < 0 || payload_len > BMKT_MAX_PAYLOAD)
        return SYNA_ERR_INVAL;
    if (payload_len && !payload)
        return SYNA_ERR_INVAL;

    buf[0] = SYNA_FW_ACE_COMMAND;
    buf[1] = BMKT_HEADER_ID;
    buf[2] = seq;
    buf[3] = msg_id;
    buf[4] = (uint8_t)payload_len;
    if (payload_len)
        memcpy(buf + 5, payload, (size_t)payload_len);

    syna_dbg("-> cmd 0x%02x seq %u payload %d", msg_id, seq, payload_len);
    return syna_bulk_out(d, buf, 1 + BMKT_HEADER_LEN + payload_len, SYNA_CMD_TIMEOUT_MS);
}

uint8_t syna_next_seq(syna_dev *d, int reuse_current)
{
    if (reuse_current)
        return d->cur_seq;
    d->last_seq = (uint8_t)((d->last_seq + 1) & 0xff);
    if (d->last_seq == 0)
        d->last_seq = 1;
    d->cur_seq = d->last_seq;
    return d->cur_seq;
}

/* --------------------------------------------------------------------------
 * Response parsing
 * ----------------------------------------------------------------------- */
static int resp_is_fail(uint8_t id)
{
    switch (id) {
    case 0x02: case 0x09: case BMKT_RSP_FPS_INIT_FAIL:
    case BMKT_RSP_FPS_MODE_FAIL:
    case BMKT_RSP_SET_SECURITY_LEVEL_FAIL:
    case BMKT_RSP_GET_SECURITY_LEVEL_FAIL:
    case BMKT_RSP_CANCEL_OP_FAIL:
    case BMKT_RSP_ENROLL_FAIL:
    case BMKT_RSP_ID_FAIL:
    case BMKT_RSP_VERIFY_FAIL:
    case BMKT_RSP_QUERY_FAIL:
    case BMKT_RSP_DEL_USER_FP_FAIL:
    case BMKT_RSP_DEL_FULL_DB_FAIL:
    case 0x93:
    case BMKT_RSP_POWER_DOWN_FAIL:
    case BMKT_RSP_GET_VERSION_FAIL:
    case 0xC3: case 0xC6:
    case BMKT_RSP_SENSOR_STATUS_FAIL:
    case 0xE5:
        return 1;
    }
    return 0;
}

static int resp_is_complete(uint8_t id)
{
    if (resp_is_fail(id))
        return 1;
    switch (id) {
    case BMKT_RSP_FPS_INIT_OK:
    case BMKT_RSP_CANCEL_OP_OK:
    case BMKT_RSP_DEL_FULL_DB_OK:
    case BMKT_RSP_DEL_USER_FP_OK:
    case BMKT_RSP_FPS_MODE_REPORT:
    case BMKT_RSP_GET_SECURITY_LEVEL_REPORT:
    case BMKT_RSP_SET_SECURITY_LEVEL_REPORT:
    case BMKT_RSP_ENROLL_OK:
    case BMKT_RSP_ID_OK:
    case BMKT_RSP_VERIFY_OK:
    case BMKT_RSP_GET_ENROLLED_FINGERS_REPORT:
    case BMKT_RSP_DATABASE_CAPACITY_REPORT:
    case BMKT_RSP_QUERY_RESPONSE_COMPLETE:
    case BMKT_RSP_VERSION_INFO:
    case BMKT_RSP_POWER_DOWN_READY:
    case BMKT_RSP_SENSOR_STATUS_REPORT:
        return 1;
    }
    return 0;
}

/* Parse [status:u16le][0xFE][seq][id][len][payload] out of a reply buffer. */
int syna_parse_reply(const uint8_t *buf, int len, syna_resp *r)
{
    const uint8_t *m;
    int mlen;

    if (len < SYNA_FW_REPLY_HEADER_LEN)
        return SYNA_ERR_PROTO;

    memset(r, 0, sizeof *r);
    r->fw_status = (uint16_t)(buf[0] | (buf[1] << 8));

    /* Firmware 6.x acknowledges an ACE command with the status word alone and
     * pushes the BMKT response out of band a moment later. */
    if (len == SYNA_FW_REPLY_HEADER_LEN) {
        r->ack_only = 1;
        return SYNA_OK;
    }

    if (len < SYNA_FW_REPLY_HEADER_LEN + BMKT_HEADER_LEN)
        return SYNA_ERR_PROTO;

    m = buf + SYNA_FW_REPLY_HEADER_LEN;
    mlen = len - SYNA_FW_REPLY_HEADER_LEN;

    if (m[0] != BMKT_HEADER_ID)
        return SYNA_ERR_PROTO;

    r->seq         = m[1];
    r->msg_id      = m[2];
    r->payload_len = m[3];
    if (r->payload_len > mlen - BMKT_HEADER_LEN)
        return SYNA_ERR_PROTO;
    r->payload  = r->payload_len ? m + BMKT_HEADER_LEN : NULL;
    r->complete = resp_is_complete(r->msg_id);
    r->is_fail  = resp_is_fail(r->msg_id);
    if (r->is_fail && r->payload_len >= 2)
        r->status = (r->payload[0] << 8) | r->payload[1];

    return SYNA_OK;
}

int syna_read_resp(syna_dev *d, uint8_t *buf, int cap, syna_resp *r, unsigned timeout_ms)
{
    int len = 0, rc;

    rc = syna_bulk_in(d, buf, cap, &len, timeout_ms);
    if (rc != SYNA_OK)
        return rc;
    rc = syna_parse_reply(buf, len, r);
    if (rc != SYNA_OK) {
        syna_dbg("malformed reply of %d bytes", len);
        return rc;
    }
    if (r->ack_only)
        syna_dbg("<- ack, fw_status %u (response pending)", r->fw_status);
    else
        syna_dbg("<- rsp 0x%02x seq %u payload %u fw_status %u",
                 r->msg_id, r->seq, r->payload_len, r->fw_status);
    return SYNA_OK;
}

/* Block until the sensor signals that an async message is waiting.
 * Returns SYNA_OK, SYNA_ERR_TIMEOUT (overall deadline hit) or SYNA_ERR_CANCELLED. */
static int wait_for_async(syna_dev *d, unsigned overall_timeout_ms, int *cancel_sent)
{
    uint8_t ibuf[SYNA_INTERRUPT_SIZE];
    uint64_t deadline = overall_timeout_ms ? now_ms() + overall_timeout_ms : 0;

    for (;;) {
        int transferred = 0, e;

        if (d->cancel_req && !*cancel_sent) {
            syna_dbg("cancellation requested, sending CANCEL_OP");
            /* Fire and forget on the current sequence number; the sensor
             * answers with CANCEL_OP_OK on the normal reply path. */
            syna_send_bmkt(d, d->cur_seq, BMKT_CMD_CANCEL_OP, NULL, 0);
            *cancel_sent = 1;
            d->cancel_req = 0;
            /* Keep waiting: the cancellation response still has to be read. */
        }

        e = libusb_interrupt_transfer(d->h, SYNA_EP_INTERRUPT, ibuf,
                                      sizeof ibuf, &transferred,
                                      SYNA_INTERRUPT_POLL_MS);
        if (e == LIBUSB_ERROR_TIMEOUT) {
            if (deadline && now_ms() >= deadline && !*cancel_sent)
                return SYNA_ERR_TIMEOUT;
            continue;
        }
        if (e != 0) {
            syna_dbg("interrupt transfer failed: %s", libusb_strerror(e));
            return usb_err(e);
        }
        if (transferred < 1)
            continue;

        syna_hexdump("INT", ibuf, transferred);
        if (ibuf[0] & SYNA_ASYNC_MESSAGE_PENDING)
            return SYNA_OK;
        /* Some other status bit toggled; keep listening. */
    }
}

/* Wait until the sensor has a message for us and ask it to send it.
 *
 * `tolerate_timeout` covers the case where the sensor answered a command but
 * never raised the interrupt: asking for the message anyway costs one transfer
 * and recovers the operation. */
static int fetch_next_message(syna_dev *d, unsigned timeout_ms,
                              int *cancel_sent, int tolerate_timeout)
{
    int rc = wait_for_async(d, timeout_ms, cancel_sent);

    if (rc == SYNA_ERR_TIMEOUT && tolerate_timeout)
        syna_dbg("no interrupt within %u ms, requesting the response anyway",
                 timeout_ms);
    else if (rc != SYNA_OK)
        return rc;

    return syna_fw_cmd(d, SYNA_FW_ASYNCMSG_READ);
}

/* --------------------------------------------------------------------------
 * The command engine
 *
 * Sends one command and pumps responses through `h` until the handler says the
 * operation is done, the sensor reports a terminal response, or an error or
 * cancellation happens.
 * ----------------------------------------------------------------------- */
int syna_run_op(syna_dev *d, uint8_t msg_id, const uint8_t *payload, int payload_len,
                syna_handler h, void *ctx, unsigned wait_timeout_ms)
{
    uint8_t buf[SYNA_MAX_TRANSFER];
    syna_followup fu;
    syna_resp r;
    int rc, cancel_sent = 0;
    uint8_t seq;

    if (!d || !d->h)
        return SYNA_ERR_INVAL;

    d->cancel_req = 0;
    seq = syna_next_seq(d, 0);

    rc = syna_send_bmkt(d, seq, msg_id, payload, payload_len);
    if (rc != SYNA_OK)
        return rc;

    for (;;) {
        rc = syna_read_resp(d, buf, sizeof buf, &r, SYNA_REPLY_TIMEOUT_MS);
        if (rc != SYNA_OK)
            return rc;

        /* The sensor only acknowledged the command; the answer is still to
         * come, so go and collect it. */
        if (r.ack_only) {
            if (r.fw_status != 0) {
                syna_dbg("command rejected with fw status %u", r.fw_status);
                return -(SYNA_ERR_SENSOR_BASE + r.fw_status);
            }
            rc = fetch_next_message(d, SYNA_ACK_WAIT_MS, &cancel_sent, 1);
            if (rc != SYNA_OK)
                return rc;
            continue;
        }

        /* Cancellation acknowledgements terminate the operation. */
        if (r.msg_id == BMKT_RSP_CANCEL_OP_OK)
            return SYNA_ERR_CANCELLED;
        if (r.msg_id == BMKT_RSP_CANCEL_OP_FAIL) {
            syna_dbg("sensor refused cancellation");
            return SYNA_ERR_PROTO;
        }

        /* Sequence number 0 marks unsolicited traffic. A general error is
         * still fatal; anything else is chatter we ignore. */
        if (r.seq == 0) {
            if (r.msg_id == BMKT_RSP_GENERAL_ERROR) {
                int st = (r.payload_len >= 2)
                       ? ((r.payload[0] << 8) | r.payload[1])
                       : BMKT_STATUS_GENERAL_ERROR;
                syna_dbg("general error %d from sensor", st);
                return -(SYNA_ERR_SENSOR_BASE + st);
            }
            syna_dbg("ignoring unsolicited message 0x%02x", r.msg_id);
            goto next_message;
        }

        if (r.seq != seq)
            syna_dbg("sequence mismatch: got %u, expected %u", r.seq, seq);

        /* Finger presence is reported out of band during any operation. */
        if (r.msg_id == BMKT_EVT_FINGER_REPORT && r.payload_len == 1) {
            int down = (r.payload[0] == 0x01);
            d->finger_on = down;
            syna_emit(d, ctx, down ? SYNA_EV_FINGER_DOWN : SYNA_EV_FINGER_UP, 0);
        }

        memset(&fu, 0, sizeof fu);
        rc = h(d, &r, ctx, &fu);
        if (rc < 0)
            return rc;

        if (fu.have) {
            uint8_t fseq = syna_next_seq(d, fu.same_seq);
            rc = syna_send_bmkt(d, fseq, fu.msg_id, fu.payload, fu.len);
            if (rc != SYNA_OK)
                return rc;
            if (!fu.same_seq)
                seq = fseq;
            continue;
        }

        if (rc == SYNA_HR_DONE)
            return SYNA_OK;

        /* Handler did not consume a failure response: surface it. */
        if (r.is_fail)
            return -(SYNA_ERR_SENSOR_BASE + r.status);

        if (r.complete)
            return SYNA_OK;

    next_message:
        rc = fetch_next_message(d, wait_timeout_ms, &cancel_sent, 0);
        if (rc != SYNA_OK) {
            if (rc == SYNA_ERR_TIMEOUT) {
                /* Try to leave the sensor in a clean state. */
                syna_send_bmkt(d, d->cur_seq, BMKT_CMD_CANCEL_OP, NULL, 0);
                cancel_sent = 1;
            }
            return rc;
        }
    }
}

void syna_emit(syna_dev *d, void *ctx, syna_event ev, int arg)
{
    syna_op_ctx *c = (syna_op_ctx *)ctx;

    if (!c || !c->cb)
        return;
    if (c->cb(ev, arg, c->user) != 0) {
        syna_dbg("callback requested cancellation");
        d->cancel_req = 1;
    }
}

/* --------------------------------------------------------------------------
 * Firmware version handshake — also serves as the "is the sensor alive?" probe
 * ----------------------------------------------------------------------- */
static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

int syna_fw_version_get(syna_dev *d, syna_fw_version *out)
{
    uint8_t buf[64];
    int len = 0, rc, attempt;

    if (!d || !d->h || !out)
        return SYNA_ERR_INVAL;

    for (attempt = 0; attempt < 2; attempt++) {
        uint16_t status;

        rc = syna_fw_cmd(d, SYNA_FW_GET_VERSION);
        if (rc != SYNA_OK)
            return rc;
        rc = syna_bulk_in(d, buf, 40, &len, SYNA_CMD_TIMEOUT_MS);
        if (rc != SYNA_OK)
            return rc;
        if (len < 28)
            return SYNA_ERR_PROTO;

        status = (uint16_t)(buf[0] | (buf[1] << 8));
        if (status != 0) {
            syna_dbg("version query returned status %u (attempt %d)", status, attempt + 1);
            continue;   /* the sensor often answers the first poll with a stale error */
        }

        out->build_time     = rd32(buf + 2);
        out->build_num      = rd32(buf + 6);
        out->version_major  = buf[10];
        out->version_minor  = buf[11];
        out->target         = buf[12];
        out->product        = buf[13];
        out->silicon_rev    = buf[14];
        out->formal_release = buf[15];
        out->platform       = buf[16];
        out->patch          = buf[17];
        memcpy(out->serial_number, buf + 18, 6);
        out->security       = (uint16_t)(buf[24] | (buf[25] << 8));
        out->iface          = buf[26];
        out->device_type    = buf[27];
        return SYNA_OK;
    }
    return SYNA_ERR_PROTO;
}

/* --------------------------------------------------------------------------
 * Open / close
 * ----------------------------------------------------------------------- */
static int fps_init_handler(syna_dev *d, const syna_resp *r, void *ctx, syna_followup *fu)
{
    (void)d; (void)fu;
    if (r->msg_id == BMKT_RSP_FPS_INIT_OK) {
        if (r->payload_len == 1)
            ((syna_op_ctx *)ctx)->u.init_finger_present = r->payload[0];
        return SYNA_HR_DONE;
    }
    return SYNA_HR_CONTINUE;
}

int syna_fps_init(syna_dev *d)
{
    syna_op_ctx ctx;
    memset(&ctx, 0, sizeof ctx);
    return syna_run_op(d, BMKT_CMD_FPS_INIT, NULL, 0, fps_init_handler, &ctx,
                       SYNA_CMD_TIMEOUT_MS * 5);
}

int syna_open(syna_dev **out, const char *serial, unsigned flags)
{
    syna_dev *d;
    syna_fw_version v;
    int rc;

    if (!out)
        return SYNA_ERR_INVAL;
    *out = NULL;

    if (getenv("SYNAFP_DEBUG"))
        syna_debug_level = atoi(getenv("SYNAFP_DEBUG"));

    d = calloc(1, sizeof *d);
    if (!d)
        return SYNA_ERR_NOMEM;
    d->op_timeout_ms = SYNA_DEFAULT_OP_TIMEOUT_MS;

    rc = libusb_init(&d->ctx);
    if (rc != 0) {
        free(d);
        return usb_err(rc);
    }

    rc = usb_bring_up(d, serial);
    if (rc != SYNA_OK)
        goto fail;

    if (flags & SYNA_OPEN_RESET) {
        rc = usb_reset_and_reopen(d, serial);
        if (rc != SYNA_OK)
            goto fail;
    }

    /* Probe. If the sensor is wedged (common after a warm boot from Windows,
     * or after a client died mid-operation) a USB reset almost always clears
     * it, so retry once through a reset before giving up. */
    rc = syna_fw_version_get(d, &v);
    if (rc != SYNA_OK && !(flags & SYNA_OPEN_RESET)) {
        syna_dbg("initial probe failed (%s), resetting sensor", syna_strerror(rc));
        if (usb_reset_and_reopen(d, serial) == SYNA_OK)
            rc = syna_fw_version_get(d, &v);
    }
    if (rc != SYNA_OK)
        goto fail;

    d->fw = v;
    syna_dbg("firmware %u.%u build %u, security 0x%04x, device type 0x%02x",
             v.version_major, v.version_minor, v.build_num, v.security, v.device_type);

    if (!(flags & SYNA_OPEN_NO_INIT)) {
        rc = syna_fps_init(d);
        if (rc != SYNA_OK) {
            /* A sensor left mid-operation answers FPS_INIT with BUSY. Cancel
             * whatever is running and try once more. */
            syna_dbg("FPS_INIT failed (%s), cancelling stale operation",
                     syna_strerror(rc));
            syna_send_bmkt(d, syna_next_seq(d, 0), BMKT_CMD_CANCEL_OP, NULL, 0);
            syna_drain(d);
            rc = syna_fps_init(d);
        }
        if (rc != SYNA_OK)
            goto fail;
    }

    *out = d;
    return SYNA_OK;

fail:
    usb_tear_down(d);
    libusb_exit(d->ctx);
    free(d);
    return rc;
}

/* Swallow any replies the sensor still owes us, so the next command starts
 * from a clean queue. */
void syna_drain(syna_dev *d)
{
    uint8_t buf[SYNA_MAX_TRANSFER];
    int i, len;

    for (i = 0; i < 8; i++) {
        if (syna_bulk_in(d, buf, sizeof buf, &len, 200) != SYNA_OK)
            break;
    }
}

void syna_close(syna_dev *d)
{
    if (!d)
        return;
    if (d->h) {
        /* Best effort: cancel anything outstanding so the sensor is not left
         * armed after we disappear. */
        syna_send_bmkt(d, d->cur_seq, BMKT_CMD_CANCEL_OP, NULL, 0);
        syna_drain(d);
    }
    usb_tear_down(d);
    if (d->ctx)
        libusb_exit(d->ctx);
    free(d);
}

int syna_cancel(syna_dev *d)
{
    if (!d)
        return SYNA_ERR_INVAL;
    d->cancel_req = 1;
    return SYNA_OK;
}

int syna_set_timeout(syna_dev *d, unsigned ms)
{
    if (!d)
        return SYNA_ERR_INVAL;
    d->op_timeout_ms = ms;
    return SYNA_OK;
}

const char *syna_serial(const syna_dev *d) { return d ? d->serial : ""; }
uint16_t syna_product_id(const syna_dev *d) { return d ? d->pid : 0; }
