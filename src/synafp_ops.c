/* synafp_ops.c - enrolment, matching and on-sensor template management.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#define _POSIX_C_SOURCE 200809L
#include "synafp_priv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *finger_names[] = {
    "unknown",
    "left-thumb",  "left-index",  "left-middle",  "left-ring",  "left-little",
    "right-thumb", "right-index", "right-middle", "right-ring", "right-little"
};

const char *syna_finger_name(uint8_t finger_id)
{
    if (finger_id < 1 || finger_id > 10)
        return "unknown";
    return finger_names[finger_id];
}

int syna_finger_from_name(const char *name)
{
    int i;
    if (!name || !*name)
        return SYNA_ERR_INVAL;
    for (i = 1; i <= 10; i++)
        if (strcmp(name, finger_names[i]) == 0)
            return i;
    /* also accept a plain number */
    if (name[0] >= '1' && name[0] <= '9') {
        int v = atoi(name);
        if (v >= 1 && v <= 10)
            return v;
    }
    return SYNA_ERR_INVAL;
}

static void copy_user_id(char *dst, size_t dstsz, const uint8_t *src, int len)
{
    if (len < 0) len = 0;
    if ((size_t)len > dstsz - 1) len = (int)dstsz - 1;
    memcpy(dst, src, (size_t)len);
    dst[len] = '\0';
}

/* --------------------------------------------------------------------------
 * Enrolment
 * ----------------------------------------------------------------------- */
static int enroll_handler(syna_dev *d, const syna_resp *r, void *ctx, syna_followup *fu)
{
    syna_op_ctx *c = ctx;
    (void)fu;

    switch (r->msg_id) {
    case BMKT_RSP_ENROLL_READY:
        syna_emit(d, ctx, SYNA_EV_READY, 0);
        return SYNA_HR_CONTINUE;

    case BMKT_RSP_CAPTURE_COMPLETE:
        syna_emit(d, ctx, SYNA_EV_CAPTURE_OK, 0);
        return SYNA_HR_CONTINUE;

    case BMKT_RSP_ENROLL_REPORT: {
        int progress;
        if (r->payload_len != 1)
            return SYNA_ERR_PROTO;
        progress = r->payload[0];
        /* Firmware repeats the same percentage when a touch produced nothing
         * usable; surface that as "try again" rather than fake progress. */
        if (progress == c->u.enroll.done && progress < 100)
            syna_emit(d, ctx, SYNA_EV_RETRY, 0);
        c->u.enroll.done = progress;
        syna_emit(d, ctx, SYNA_EV_ENROLL_PROGRESS, progress);
        return SYNA_HR_CONTINUE;
    }

    case BMKT_RSP_ENROLL_PAUSED:
    case BMKT_RSP_ENROLL_RESUMED:
        return SYNA_HR_CONTINUE;

    case BMKT_RSP_ENROLL_OK:
        if (r->payload_len < 1)
            return SYNA_ERR_PROTO;
        syna_emit(d, ctx, SYNA_EV_ENROLL_PROGRESS, 100);
        return SYNA_HR_DONE;
    }
    return SYNA_HR_CONTINUE;
}

int syna_enroll(syna_dev *d, const char *user_id, uint8_t finger,
                syna_cb cb, void *user)
{
    uint8_t payload[2 + BMKT_MAX_USER_ID_LEN];
    syna_op_ctx ctx;
    size_t idlen;

    if (!d || !user_id || !*user_id)
        return SYNA_ERR_INVAL;
    if (finger < 1 || finger > 10)
        return SYNA_ERR_INVAL;

    idlen = strlen(user_id);
    if (idlen > BMKT_MAX_USER_ID_LEN)
        idlen = BMKT_MAX_USER_ID_LEN;

    payload[0] = 0;         /* backup options: unsupported on Prometheus */
    payload[1] = finger;
    memcpy(payload + 2, user_id, idlen);

    memset(&ctx, 0, sizeof ctx);
    ctx.cb = cb;
    ctx.user = user;
    ctx.u.enroll.done = -1;

    return syna_run_op(d, BMKT_CMD_ENROLL_USER, payload, (int)(idlen + 2),
                       enroll_handler, &ctx, d->op_timeout_ms);
}

/* --------------------------------------------------------------------------
 * Verification (1:1 against a known user id)
 * ----------------------------------------------------------------------- */
static int parse_match(const syna_resp *r, syna_match *m)
{
    if (r->payload_len < 3)
        return SYNA_ERR_PROTO;
    m->matched   = 1;
    m->score     = (double)r->payload[0] + 0.01 * (double)r->payload[1];
    m->finger_id = r->payload[2];
    copy_user_id(m->user_id, sizeof m->user_id, r->payload + 3, r->payload_len - 3);
    return SYNA_OK;
}

static int verify_handler(syna_dev *d, const syna_resp *r, void *ctx, syna_followup *fu)
{
    syna_op_ctx *c = ctx;
    (void)fu;

    switch (r->msg_id) {
    case BMKT_RSP_VERIFY_READY:
    case BMKT_RSP_ID_READY:
        syna_emit(d, ctx, SYNA_EV_READY, 0);
        return SYNA_HR_CONTINUE;

    case BMKT_RSP_CAPTURE_COMPLETE:
        syna_emit(d, ctx, SYNA_EV_CAPTURE_OK, 0);
        return SYNA_HR_CONTINUE;

    case BMKT_RSP_VERIFY_OK:
    case BMKT_RSP_ID_OK: {
        int rc = parse_match(r, c->u.match.out);
        return rc == SYNA_OK ? SYNA_HR_DONE : rc;
    }

    case BMKT_RSP_VERIFY_FAIL:
    case BMKT_RSP_ID_FAIL:
        /* A rejected finger is a normal outcome, not a driver error. Only
         * genuine faults propagate as errors. */
        if (r->status == BMKT_STATUS_NO_MATCH) {
            c->u.match.out->matched = 0;
            return SYNA_HR_DONE;
        }
        if (r->status == BMKT_STATUS_STIMULUS_ERROR ||
            r->status == BMKT_STATUS_INVALID_FP_IMAGE ||
            r->status == BMKT_STATUS_FEATURE_EXTRACT_FAIL) {
            syna_emit(d, ctx, SYNA_EV_RETRY, r->status);
            c->u.match.out->matched = 0;
            return SYNA_HR_DONE;
        }
        return -(SYNA_ERR_SENSOR_BASE + r->status);
    }
    return SYNA_HR_CONTINUE;
}

int syna_verify(syna_dev *d, const char *user_id, syna_match *out,
                syna_cb cb, void *user)
{
    syna_op_ctx ctx;
    size_t idlen;

    if (!d || !user_id || !*user_id || !out)
        return SYNA_ERR_INVAL;

    idlen = strlen(user_id);
    if (idlen > BMKT_MAX_USER_ID_LEN)
        idlen = BMKT_MAX_USER_ID_LEN;

    memset(out, 0, sizeof *out);
    memset(&ctx, 0, sizeof ctx);
    ctx.cb = cb;
    ctx.user = user;
    ctx.u.match.out = out;

    return syna_run_op(d, BMKT_CMD_VERIFY_USER, (const uint8_t *)user_id, (int)idlen,
                       verify_handler, &ctx, d->op_timeout_ms);
}

/* --------------------------------------------------------------------------
 * Identification (1:N against a caller-supplied candidate list)
 *
 * The sensor only accepts one candidate id per message, so it asks for the
 * next one with SEND_NEXT_USER_ID until the list is exhausted.
 * ----------------------------------------------------------------------- */
static int push_next_id(syna_op_ctx *c, syna_followup *fu)
{
    const char *id;
    size_t len;
    int off = 0;

    if (c->u.ident.next >= c->u.ident.n)
        return 0;

    id = c->u.ident.ids[c->u.ident.next++];
    len = strlen(id);
    if (len > BMKT_MAX_USER_ID_LEN)
        len = BMKT_MAX_USER_ID_LEN;

    fu->payload[off++] = 1;              /* one id in this message */
    fu->payload[off++] = (uint8_t)len;
    memcpy(fu->payload + off, id, len);
    off += (int)len;

    fu->have     = 1;
    fu->same_seq = 1;
    fu->msg_id   = BMKT_CMD_ID_NEXT_USER;
    fu->len      = off;
    return 1;
}

static int identify_handler(syna_dev *d, const syna_resp *r, void *ctx, syna_followup *fu)
{
    syna_op_ctx *c = ctx;

    if (r->msg_id == BMKT_RSP_SEND_NEXT_USER_ID) {
        if (push_next_id(c, fu))
            return SYNA_HR_CONTINUE;
        return SYNA_HR_CONTINUE;   /* nothing left; wait for the verdict */
    }
    return verify_handler(d, r, ctx, fu);
}

int syna_identify(syna_dev *d, const char *const *user_ids, int n_ids,
                  syna_match *out, syna_cb cb, void *user)
{
    uint8_t payload[3 + BMKT_MAX_USER_ID_LEN];
    syna_op_ctx ctx;
    size_t len;
    int off = 0;

    if (!d || !user_ids || n_ids <= 0 || !out)
        return SYNA_ERR_INVAL;
    if (n_ids > 255)
        return SYNA_ERR_INVAL;

    memset(out, 0, sizeof *out);
    memset(&ctx, 0, sizeof ctx);
    ctx.cb = cb;
    ctx.user = user;
    ctx.u.ident.ids  = user_ids;
    ctx.u.ident.n    = n_ids;
    ctx.u.ident.next = 1;       /* the first id travels in the opening message */
    ctx.u.ident.out  = out;
    ctx.u.match.out  = out;     /* verify_handler reads it from here */

    len = strlen(user_ids[0]);
    if (len > BMKT_MAX_USER_ID_LEN)
        len = BMKT_MAX_USER_ID_LEN;

    payload[off++] = (uint8_t)n_ids;     /* total candidates */
    payload[off++] = 1;                  /* candidates in this message */
    payload[off++] = (uint8_t)len;
    memcpy(payload + off, user_ids[0], len);
    off += (int)len;

    return syna_run_op(d, BMKT_CMD_ID_USER_IN_ORDER, payload, off,
                       identify_handler, &ctx, d->op_timeout_ms);
}

/* --------------------------------------------------------------------------
 * On-sensor template enumeration
 *
 * Record layout inside TEMPLATE_RECORDS_REPORT:
 *   [total_messages][message_index]  then, repeated:
 *   [user_id_len + 2][template_status][finger_id][user_id ...]
 * ----------------------------------------------------------------------- */
static int list_handler(syna_dev *d, const syna_resp *r, void *ctx, syna_followup *fu)
{
    syna_op_ctx *c = ctx;
    int off = 0;
    (void)d;

    if (r->msg_id == BMKT_RSP_QUERY_RESPONSE_COMPLETE)
        return SYNA_HR_DONE;

    if (r->msg_id != BMKT_RSP_TEMPLATE_RECORDS_REPORT)
        return SYNA_HR_CONTINUE;

    if (r->payload_len < 2)
        return SYNA_ERR_PROTO;

    c->u.list.total_msgs = r->payload[off++];
    c->u.list.got_msgs   = r->payload[off++];

    while (off < r->payload_len) {
        int reclen, idlen;

        reclen = r->payload[off++];
        if (reclen < 2)
            return SYNA_ERR_PROTO;
        idlen = reclen - 2;
        if (idlen > BMKT_MAX_USER_ID_LEN)
            return SYNA_ERR_PROTO;
        if (off + 2 + idlen > r->payload_len)
            return SYNA_ERR_PROTO;

        if (c->u.list.count < c->u.list.max) {
            syna_template *t = &c->u.list.out[c->u.list.count];
            t->template_status = r->payload[off];
            t->finger_id       = r->payload[off + 1];
            copy_user_id(t->user_id, sizeof t->user_id, r->payload + off + 2, idlen);
            c->u.list.count++;
        }
        off += 2 + idlen;
    }

    /* Ask for the next chunk if the sensor said there is one. */
    if (c->u.list.got_msgs < c->u.list.total_msgs) {
        fu->have     = 1;
        fu->same_seq = 1;
        fu->msg_id   = BMKT_CMD_GET_NEXT_QUERY_RESPONSE;
        fu->len      = 0;
    }
    return SYNA_HR_CONTINUE;
}

int syna_list(syna_dev *d, syna_template *out, int max, int *count)
{
    syna_op_ctx ctx;
    int rc;

    if (!d || !out || max <= 0 || !count)
        return SYNA_ERR_INVAL;

    memset(&ctx, 0, sizeof ctx);
    ctx.u.list.out = out;
    ctx.u.list.max = max;

    rc = syna_run_op(d, BMKT_CMD_GET_TEMPLATE_RECORDS, NULL, 0,
                     list_handler, &ctx, SYNA_CMD_TIMEOUT_MS * 10);

    /* An empty database is reported as a failure by some firmware revisions. */
    if (SYNA_IS_SENSOR_ERR(rc) && SYNA_SENSOR_STATUS(rc) == BMKT_STATUS_DATABASE_EMPTY) {
        *count = 0;
        return SYNA_OK;
    }
    *count = ctx.u.list.count;
    return rc;
}

/* --------------------------------------------------------------------------
 * Deletion
 * ----------------------------------------------------------------------- */
static int delete_handler(syna_dev *d, const syna_resp *r, void *ctx, syna_followup *fu)
{
    (void)d; (void)ctx; (void)fu;
    if (r->msg_id == BMKT_RSP_DEL_USER_FP_OK)
        return SYNA_HR_DONE;
    return SYNA_HR_CONTINUE;
}

int syna_delete(syna_dev *d, const char *user_id, uint8_t finger)
{
    uint8_t payload[1 + BMKT_MAX_USER_ID_LEN];
    syna_op_ctx ctx;
    size_t idlen;

    if (!d || !user_id || !*user_id)
        return SYNA_ERR_INVAL;
    if (finger < 1 || finger > 10)
        return SYNA_ERR_INVAL;

    idlen = strlen(user_id);
    if (idlen > BMKT_MAX_USER_ID_LEN)
        idlen = BMKT_MAX_USER_ID_LEN;

    payload[0] = finger;
    memcpy(payload + 1, user_id, idlen);

    memset(&ctx, 0, sizeof ctx);
    return syna_run_op(d, BMKT_CMD_DEL_USER_FP, payload, (int)(idlen + 1),
                       delete_handler, &ctx, SYNA_CMD_TIMEOUT_MS * 10);
}

static int clear_handler(syna_dev *d, const syna_resp *r, void *ctx, syna_followup *fu)
{
    (void)fu;
    if (r->msg_id == BMKT_RSP_DELETE_PROGRESS && r->payload_len == 1) {
        syna_emit(d, ctx, SYNA_EV_DELETE_PROGRESS, r->payload[0]);
        return SYNA_HR_CONTINUE;
    }
    if (r->msg_id == BMKT_RSP_DEL_FULL_DB_OK)
        return SYNA_HR_DONE;
    return SYNA_HR_CONTINUE;
}

int syna_clear(syna_dev *d, syna_cb cb, void *user)
{
    syna_op_ctx ctx;

    if (!d)
        return SYNA_ERR_INVAL;

    memset(&ctx, 0, sizeof ctx);
    ctx.cb = cb;
    ctx.user = user;
    return syna_run_op(d, BMKT_CMD_DEL_FULL_DB, NULL, 0,
                       clear_handler, &ctx, SYNA_CMD_TIMEOUT_MS * 30);
}

/* --------------------------------------------------------------------------
 * Informational queries
 * ----------------------------------------------------------------------- */
static int capacity_handler(syna_dev *d, const syna_resp *r, void *ctx, syna_followup *fu)
{
    syna_op_ctx *c = ctx;
    (void)d; (void)fu;

    if (r->msg_id != BMKT_RSP_DATABASE_CAPACITY_REPORT)
        return SYNA_HR_CONTINUE;
    if (r->payload_len < 2)
        return SYNA_ERR_PROTO;

    c->u.cap.out->total = r->payload[0];
    c->u.cap.out->empty = r->payload[1];
    if (r->payload_len >= 4) {
        c->u.cap.out->bad_slots         = r->payload[2];
        c->u.cap.out->corrupt_templates = r->payload[3];
        c->u.cap.out->has_extended      = 1;
    }
    return SYNA_HR_DONE;
}

int syna_capacity_get(syna_dev *d, syna_capacity *out)
{
    syna_op_ctx ctx;

    if (!d || !out)
        return SYNA_ERR_INVAL;
    memset(out, 0, sizeof *out);
    memset(&ctx, 0, sizeof ctx);
    ctx.u.cap.out = out;
    return syna_run_op(d, BMKT_CMD_GET_DATABASE_CAPACITY, NULL, 0,
                       capacity_handler, &ctx, SYNA_CMD_TIMEOUT_MS * 5);
}

static int ace_version_handler(syna_dev *d, const syna_resp *r, void *ctx, syna_followup *fu)
{
    syna_op_ctx *c = ctx;
    (void)d; (void)fu;

    if (r->msg_id != BMKT_RSP_VERSION_INFO)
        return SYNA_HR_CONTINUE;
    if (r->payload_len != 15)
        return SYNA_ERR_PROTO;

    memcpy(c->u.ver.out->part, r->payload, BMKT_PART_NUM_LEN);
    c->u.ver.out->part[BMKT_PART_NUM_LEN] = '\0';
    c->u.ver.out->year  = r->payload[10];
    c->u.ver.out->week  = r->payload[11];
    c->u.ver.out->patch = r->payload[12];
    memcpy(c->u.ver.out->supplier_id, r->payload + 13, BMKT_SUPPLIER_ID_LEN);
    c->u.ver.out->supplier_id[BMKT_SUPPLIER_ID_LEN] = '\0';
    return SYNA_HR_DONE;
}

int syna_ace_version_get(syna_dev *d, syna_ace_version *out)
{
    syna_op_ctx ctx;

    if (!d || !out)
        return SYNA_ERR_INVAL;
    memset(out, 0, sizeof *out);
    memset(&ctx, 0, sizeof ctx);
    ctx.u.ver.out = out;
    return syna_run_op(d, BMKT_CMD_GET_VERSION, NULL, 0,
                       ace_version_handler, &ctx, SYNA_CMD_TIMEOUT_MS * 5);
}

static int status_handler(syna_dev *d, const syna_resp *r, void *ctx, syna_followup *fu)
{
    syna_op_ctx *c = ctx;
    size_t n;
    (void)d; (void)fu;

    if (r->msg_id != BMKT_RSP_SENSOR_STATUS_REPORT)
        return SYNA_HR_CONTINUE;

    n = r->payload_len;
    if (n > c->u.raw.cap)
        n = c->u.raw.cap;
    if (n && r->payload)
        memcpy(c->u.raw.buf, r->payload, n);
    *c->u.raw.len = n;
    return SYNA_HR_DONE;
}

int syna_sensor_status(syna_dev *d, uint8_t *buf, size_t cap, size_t *len)
{
    syna_op_ctx ctx;

    if (!d || !buf || !len)
        return SYNA_ERR_INVAL;
    *len = 0;
    memset(&ctx, 0, sizeof ctx);
    ctx.u.raw.buf = buf;
    ctx.u.raw.cap = cap;
    ctx.u.raw.len = len;
    return syna_run_op(d, BMKT_CMD_SENSOR_STATUS, NULL, 0,
                       status_handler, &ctx, SYNA_CMD_TIMEOUT_MS * 5);
}

static int power_down_handler(syna_dev *d, const syna_resp *r, void *ctx, syna_followup *fu)
{
    (void)d; (void)ctx; (void)fu;
    if (r->msg_id == BMKT_RSP_POWER_DOWN_READY)
        return SYNA_HR_DONE;
    return SYNA_HR_CONTINUE;
}

int syna_power_down(syna_dev *d)
{
    syna_op_ctx ctx;

    if (!d)
        return SYNA_ERR_INVAL;
    memset(&ctx, 0, sizeof ctx);
    return syna_run_op(d, BMKT_CMD_POWER_DOWN_NOTIFY, NULL, 0,
                       power_down_handler, &ctx, SYNA_CMD_TIMEOUT_MS * 5);
}
