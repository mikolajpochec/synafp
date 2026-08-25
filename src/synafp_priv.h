/* synafp_priv.h - internals shared between the library translation units.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#ifndef SYNAFP_PRIV_H
#define SYNAFP_PRIV_H

#include "synafp.h"

#include <libusb-1.0/libusb.h>
#include <signal.h>
#include <stdarg.h>

/* Milliseconds. The reply timeout only ever covers a message the sensor has
 * already told us is waiting, so it can be short. The interrupt poll interval
 * bounds how quickly a cancellation is noticed. */
#define SYNA_CMD_TIMEOUT_MS         1000
#define SYNA_REPLY_TIMEOUT_MS       5000
#define SYNA_INTERRUPT_POLL_MS      250
/* How long to wait for the sensor to announce the response to a command it
 * has merely acknowledged. Older firmware sometimes skips the interrupt, so
 * this timeout is advisory: we poll for the response either way. */
#define SYNA_ACK_WAIT_MS            2000
#define SYNA_DEFAULT_OP_TIMEOUT_MS  30000

struct syna_dev {
    libusb_context       *ctx;
    libusb_device_handle *h;
    int                   ifnum;
    uint16_t              pid;
    char                  serial[64];

    uint8_t               last_seq;
    uint8_t               cur_seq;

    volatile sig_atomic_t cancel_req;
    int                   finger_on;
    unsigned              op_timeout_ms;

    syna_fw_version       fw;
};

typedef struct {
    uint16_t       fw_status;
    uint8_t        seq;
    uint8_t        msg_id;
    uint8_t        payload_len;
    const uint8_t *payload;
    int            status;      /* sensor status parsed out of a *_FAIL reply */
    int            complete;
    int            is_fail;
    int            ack_only;   /* bare FW status, BMKT response follows async */
} syna_resp;

/* A handler may queue exactly one follow-up command per response. */
typedef struct {
    int     have;
    int     same_seq;   /* continue the current operation's sequence number */
    uint8_t msg_id;
    uint8_t payload[BMKT_MAX_PAYLOAD];
    int     len;
} syna_followup;

#define SYNA_HR_CONTINUE 0
#define SYNA_HR_DONE     1

/* Context handed to every handler. The union carries per-operation results. */
typedef struct {
    syna_cb cb;
    void   *user;
    union {
        uint8_t init_finger_present;
        struct {
            syna_match *out;
        } match;
        struct {
            syna_template *out;
            int            max;
            int            count;
            int            total_msgs;
            int            got_msgs;
        } list;
        struct {
            const char *user_id;
            int         user_id_len;
            uint8_t     finger;
            int         done;
        } enroll;
        struct {
            syna_capacity *out;
        } cap;
        struct {
            syna_ace_version *out;
        } ver;
        struct {
            uint8_t *buf;
            size_t   cap;
            size_t  *len;
        } raw;
        struct {
            const char *const *ids;
            int                n;
            int                next;
            syna_match        *out;
        } ident;
    } u;
} syna_op_ctx;

typedef int (*syna_handler)(syna_dev *d, const syna_resp *r, void *ctx,
                            syna_followup *fu);

/* core */
extern int syna_debug_level;
void syna_dbg(const char *fmt, ...);
void syna_hexdump(const char *tag, const uint8_t *b, int n);

int  syna_bulk_out(syna_dev *d, const uint8_t *buf, int len, unsigned timeout_ms);
int  syna_bulk_in(syna_dev *d, uint8_t *buf, int cap, int *out_len, unsigned timeout_ms);
int  syna_fw_cmd(syna_dev *d, uint8_t cmd);
int  syna_send_bmkt(syna_dev *d, uint8_t seq, uint8_t msg_id,
                    const uint8_t *payload, int payload_len);
uint8_t syna_next_seq(syna_dev *d, int reuse_current);
int  syna_parse_reply(const uint8_t *buf, int len, syna_resp *r);
int  syna_read_resp(syna_dev *d, uint8_t *buf, int cap, syna_resp *r, unsigned timeout_ms);
int  syna_run_op(syna_dev *d, uint8_t msg_id, const uint8_t *payload, int payload_len,
                 syna_handler h, void *ctx, unsigned wait_timeout_ms);
void syna_emit(syna_dev *d, void *ctx, syna_event ev, int arg);
void syna_drain(syna_dev *d);
int  syna_fps_init(syna_dev *d);

/* public but declared here too, see synafp.h */
int  syna_set_timeout(syna_dev *d, unsigned ms);

#endif /* SYNAFP_PRIV_H */
