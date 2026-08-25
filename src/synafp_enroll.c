/* synafp_enroll.c - enrolling a finger and storing it on the sensor.
 *
 * Enrolment is iterative: each touch is captured, fed to the sensor's
 * template builder, and folded into a running template. The sensor decides
 * when it has enough, which it signals by returning a template id. Only then
 * is a user and finger record written to the on-flash database.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#define _POSIX_C_SOURCE 200809L
#include "synafp_priv.h"

#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ENROLL_MAGIC_LEN 0x38   /* fixed-size header on each template chunk */

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static void wr16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

int syna_subtype_from_name(const char *name)
{
    static const struct { const char *n; uint16_t v; } t[] = {
        { "right-thumb", 0xf5 }, { "right-index",  0xf6 }, { "right-middle", 0xf7 },
        { "right-ring",  0xf8 }, { "right-little", 0xf9 }, { "left-thumb",   0xfa },
        { "left-index",  0xfb }, { "left-middle",  0xfc }, { "left-ring",    0xfd },
        { "left-little", 0xfe }
    };
    size_t i;

    if (!name)
        return SYNA_ERR_INVAL;
    for (i = 0; i < sizeof t / sizeof t[0]; i++)
        if (!strcmp(name, t[i].n))
            return (int)t[i].v;
    return SYNA_ERR_INVAL;
}

/* --------------------------------------------------------------------------
 * Identity
 *
 * The database keys users by Windows SID, so a Linux user needs one
 * synthesised. Deriving it from the username keeps it stable across
 * enrolments without needing any host-side state.
 * ----------------------------------------------------------------------- */
int syna_identity_for_user(const char *username, syna_buf *out)
{
    uint8_t digest[32], sid[8 + 5 * 4], wrapped[0x4c];
    uint32_t sub[5];
    size_t sidlen;
    int i;

    if (!username || !*username || !out)
        return SYNA_ERR_INVAL;

    SHA256((const unsigned char *)username, strlen(username), digest);

    sub[0] = 21;                       /* the usual "not built-in" authority */
    for (i = 0; i < 4; i++)
        sub[i + 1] = (uint32_t)digest[i * 4] | ((uint32_t)digest[i * 4 + 1] << 8) |
                     ((uint32_t)digest[i * 4 + 2] << 16) | ((uint32_t)digest[i * 4 + 3] << 24);

    /* SID: revision, sub-authority count, then a 48-bit big-endian authority. */
    sid[0] = 1;
    sid[1] = 5;
    sid[2] = 0; sid[3] = 0;            /* authority >> 32 */
    sid[4] = 0; sid[5] = 0; sid[6] = 0; sid[7] = 5;   /* authority = 5 */
    for (i = 0; i < 5; i++)
        wr32(sid + 8 + i * 4, sub[i]);
    sidlen = sizeof sid;

    /* Wrapped as a tagged union, zero padded to the minimum Windows size:
     * lookups treat differing lengths as different keys. */
    memset(wrapped, 0, sizeof wrapped);
    wr32(wrapped, 3);
    wr32(wrapped + 4, (uint32_t)sidlen);
    memcpy(wrapped + 8, sid, sidlen);

    out->len = 0;
    return syna_buf_add(out, wrapped, sizeof wrapped);
}

/* --------------------------------------------------------------------------
 * Database writes
 * ----------------------------------------------------------------------- */
int syna_db_user_storage(syna_dev *d, const char *name, uint16_t *dbid)
{
    uint8_t cmd[64];
    syna_buf reply = { 0 };
    size_t namelen;
    int rc;

    if (!d || !name || !dbid)
        return SYNA_ERR_INVAL;
    namelen = strlen(name) + 1;          /* the sensor wants the NUL */
    if (namelen + 5 > sizeof cmd)
        return SYNA_ERR_INVAL;

    cmd[0] = VCSFW_CMD_DB_STORAGE;
    wr16(cmd + 1, 0);                    /* look up by name, not by id */
    wr16(cmd + 3, (uint16_t)namelen);
    memcpy(cmd + 5, name, namelen);

    rc = syna_vcsfw_cmd(d, cmd, 5 + namelen, &reply);
    if (rc != SYNA_OK)
        goto done;
    if (reply.len < 2) { rc = SYNA_ERR_PROTO; goto done; }
    if (rd16(reply.p) == 0x04b3) { rc = SYNA_ERR_NOT_FOUND; goto done; }
    if (rd16(reply.p) != 0) { rc = -(SYNA_ERR_SENSOR_BASE + rd16(reply.p)); goto done; }
    if (reply.len < 10) { rc = SYNA_ERR_PROTO; goto done; }

    *dbid = rd16(reply.p + 2);
    rc = SYNA_OK;
done:
    syna_buf_free(&reply);
    return rc;
}

int syna_db_lookup_user(syna_dev *d, uint16_t storage, const uint8_t *ident,
                        size_t ident_len, uint16_t *dbid)
{
    uint8_t cmd[7 + 0x4c];
    syna_buf reply = { 0 };
    int rc;

    if (ident_len + 7 > sizeof cmd)
        return SYNA_ERR_INVAL;

    cmd[0] = VCSFW_CMD_DB_USER;
    wr16(cmd + 1, 0);
    wr16(cmd + 3, storage);
    wr16(cmd + 5, (uint16_t)ident_len);
    memcpy(cmd + 7, ident, ident_len);

    rc = syna_vcsfw_cmd(d, cmd, 7 + ident_len, &reply);
    if (rc != SYNA_OK)
        goto done;
    if (reply.len < 2) { rc = SYNA_ERR_PROTO; goto done; }
    if (rd16(reply.p) == 0x04b3) { rc = SYNA_ERR_NOT_FOUND; goto done; }
    if (rd16(reply.p) != 0) { rc = -(SYNA_ERR_SENSOR_BASE + rd16(reply.p)); goto done; }
    if (reply.len < 10) { rc = SYNA_ERR_PROTO; goto done; }

    *dbid = rd16(reply.p + 2);
    rc = SYNA_OK;
done:
    syna_buf_free(&reply);
    return rc;
}

int syna_db_new_record(syna_dev *d, uint16_t parent, uint16_t type, uint16_t storage,
                       const uint8_t *data, size_t len, uint16_t *recid)
{
    syna_buf cmd = { 0 }, reply = { 0 };
    syna_db_info_t info;
    uint8_t hdr[9];
    int rc;

    /* The reference implementation always asks for db info first. */
    syna_db_info(d, &info);

    if ((rc = syna_write_enable(d)) != SYNA_OK)
        return rc;

    hdr[0] = VCSFW_CMD_DB_NEW_RECORD;
    wr16(hdr + 1, parent);
    wr16(hdr + 3, type);
    wr16(hdr + 5, storage);
    wr16(hdr + 7, (uint16_t)len);

    if ((rc = syna_buf_add(&cmd, hdr, sizeof hdr)) != SYNA_OK) goto done;
    if ((rc = syna_buf_add(&cmd, data, len)) != SYNA_OK) goto done;

    rc = syna_vcsfw_call(d, cmd.p, cmd.len, &reply);
    if (rc == SYNA_OK) {
        if (reply.len < 4)
            rc = SYNA_ERR_PROTO;
        else if (recid)
            *recid = rd16(reply.p + 2);
    }
done:
    syna_call_cleanups(d);
    syna_buf_free(&cmd);
    syna_buf_free(&reply);
    return rc;
}

/* --------------------------------------------------------------------------
 * Enrolment primitives
 * ----------------------------------------------------------------------- */
static int enrollment_begin(syna_dev *d)
{
    uint8_t cmd[5];
    syna_buf reply = { 0 };
    int rc;

    cmd[0] = VCSFW_CMD_ENROLL_CTL;
    wr32(cmd + 1, 1);
    rc = syna_vcsfw_call(d, cmd, sizeof cmd, &reply);
    syna_buf_free(&reply);
    return rc;
}

static int enrollment_end(syna_dev *d)
{
    uint8_t cmd[5];
    syna_buf reply = { 0 };
    int rc;

    cmd[0] = VCSFW_CMD_ENROLL_CTL;
    wr32(cmd + 1, 0);
    rc = syna_vcsfw_call(d, cmd, sizeof cmd, &reply);
    syna_buf_free(&reply);
    return rc;
}

static int enrollment_update_start(syna_dev *d, uint32_t key, uint32_t *new_key)
{
    uint8_t cmd[9], ibuf[64];
    syna_buf reply = { 0 };
    int ilen = 0, rc;

    cmd[0] = VCSFW_CMD_ENROLL_UPDATE_START;
    wr32(cmd + 1, key);
    wr32(cmd + 5, 0);

    rc = syna_vcsfw_call(d, cmd, sizeof cmd, &reply);
    if (rc != SYNA_OK)
        goto done;
    if (reply.len < 6) { rc = SYNA_ERR_PROTO; goto done; }
    *new_key = (uint32_t)reply.p[2] | ((uint32_t)reply.p[3] << 8) |
               ((uint32_t)reply.p[4] << 16) | ((uint32_t)reply.p[5] << 24);

    syna_wait_interrupt(d, ibuf, sizeof ibuf, &ilen, 5000);
    rc = SYNA_OK;
done:
    syna_buf_free(&reply);
    return rc;
}

/* Feed the running template back to the sensor and collect the updated one. */
static int enrollment_update(syna_dev *d, const syna_buf *prev, syna_buf *out)
{
    syna_buf cmd = { 0 }, reply = { 0 };
    uint8_t op = VCSFW_CMD_ENROLL_UPDATE;
    int rc;

    if ((rc = syna_write_enable(d)) != SYNA_OK)
        return rc;

    if ((rc = syna_buf_add(&cmd, &op, 1)) != SYNA_OK) goto done;
    if (prev->len && (rc = syna_buf_add(&cmd, prev->p, prev->len)) != SYNA_OK) goto done;

    rc = syna_vcsfw_call(d, cmd.p, cmd.len, &reply);
    if (rc == SYNA_OK && out) {
        out->len = 0;
        rc = syna_buf_add(out, reply.p + 2, reply.len - 2);
    }
done:
    syna_call_cleanups(d);
    syna_buf_free(&cmd);
    syna_buf_free(&reply);
    return rc;
}

/* One touch folded into the template. Returns a template id once the sensor
 * decides enrolment is complete. */
static int append_new_image(syna_dev *d, syna_buf *template_,
                            syna_buf *tid, int *progress)
{
    syna_buf res = { 0 };
    uint8_t ibuf[64];
    const uint8_t *p;
    size_t len;
    uint16_t declared;
    int ilen = 0, rc;

    if ((rc = enrollment_update(d, template_, NULL)) != SYNA_OK)
        goto done;

    syna_wait_interrupt(d, ibuf, sizeof ibuf, &ilen, 5000);

    if ((rc = enrollment_update(d, template_, &res)) != SYNA_OK)
        goto done;

    if (res.len < 2) { rc = SYNA_ERR_PROTO; goto done; }
    declared = rd16(res.p);
    p = res.p + 2;
    len = res.len - 2;
    if (declared != len) {
        syna_dbg("enrol response length mismatch: %u declared, %zu present",
                 declared, len);
        rc = SYNA_ERR_PROTO;
        goto done;
    }

    tid->len = 0;
    while (len >= 4) {
        uint16_t tag = rd16(p);
        uint16_t l   = rd16(p + 2);
        size_t chunk = ENROLL_MAGIC_LEN + (size_t)l;

        if (chunk > len) { rc = SYNA_ERR_PROTO; goto done; }

        syna_dbg("enrol chunk: tag %u, length %u", tag, l);

        if (tag == 0) {
            template_->len = 0;
            if ((rc = syna_buf_add(template_, p, chunk)) != SYNA_OK) goto done;
        } else if (tag == 1 && progress) {
            /* Not a percentage: a bitmask with one bit per enrolment stage
             * the sensor has satisfied. */
            if (l >= 2)
                *progress = rd16(p + ENROLL_MAGIC_LEN);
        } else if (tag == 3) {
            if ((rc = syna_buf_add(tid, p + ENROLL_MAGIC_LEN, l)) != SYNA_OK) goto done;
            syna_dbg("sensor issued a template id (%u bytes): enrolment complete", l);
        } else {
            syna_dbg("ignoring unknown enrol chunk tag %u", tag);
        }

        p   += chunk;
        len -= chunk;
    }
    rc = SYNA_OK;
done:
    syna_buf_free(&res);
    return rc;
}

static int make_finger_data(uint16_t subtype, const syna_buf *template_,
                            const syna_buf *tid, syna_buf *out)
{
    uint8_t hdr[8];
    static const uint8_t tail[0x20] = { 0 };
    size_t tinfo_len;
    int rc;

    tinfo_len = 4 + template_->len + 4 + tid->len;

    wr16(hdr + 0, subtype);
    wr16(hdr + 2, 3);
    wr16(hdr + 4, (uint16_t)tinfo_len);
    wr16(hdr + 6, 0x20);

    out->len = 0;
    if ((rc = syna_buf_add(out, hdr, sizeof hdr)) != SYNA_OK) return rc;

    wr16(hdr + 0, 1);
    wr16(hdr + 2, (uint16_t)template_->len);
    if ((rc = syna_buf_add(out, hdr, 4)) != SYNA_OK) return rc;
    if ((rc = syna_buf_add(out, template_->p, template_->len)) != SYNA_OK) return rc;

    wr16(hdr + 0, 2);
    wr16(hdr + 2, (uint16_t)tid->len);
    if ((rc = syna_buf_add(out, hdr, 4)) != SYNA_OK) return rc;
    if ((rc = syna_buf_add(out, tid->p, tid->len)) != SYNA_OK) return rc;

    return syna_buf_add(out, tail, sizeof tail);
}

int syna_enroll(syna_dev *d, const char *username, uint16_t subtype,
                syna_enroll_cb cb, void *user)
{
    syna_buf template_ = { 0 }, tid = { 0 }, ident = { 0 }, finger = { 0 };
    syna_capture_result cr;
    uint16_t storage = 0, userid = 0, recid = 0;
    uint32_t key = 0;
    uint8_t ibuf[64];
    int ilen = 0, rc, touches = 0, progress = 0;

    if (!d || !username)
        return SYNA_ERR_INVAL;
    if (!d->type_info && (rc = syna_sensor_setup(d)) != SYNA_OK)
        return rc;

    if ((rc = syna_identity_for_user(username, &ident)) != SYNA_OK)
        goto out;

    rc = syna_db_user_storage(d, "StgWindsor", &storage);
    if (rc != SYNA_OK) {
        syna_dbg("no user storage on the sensor: %s", syna_strerror(rc));
        goto out;
    }

    if ((rc = enrollment_begin(d)) != SYNA_OK)
        goto out;

    for (;;) {
        syna_glow_start(d);

        if (cb && cb(SYNA_ENROLL_TOUCH, touches, progress, user) != 0) {
            rc = SYNA_ERR_CANCELLED;
            break;
        }

        rc = syna_capture(d, SYNA_CAPTURE_ENROLL, &cr);
        if (rc != SYNA_OK) {
            enrollment_end(d);
            if (rc == SYNA_ERR_CANCELLED || rc == SYNA_ERR_TIMEOUT)
                break;
            /* A bad touch is recoverable: tell the caller and go round again. */
            if (cb && cb(SYNA_ENROLL_RETRY, touches, progress, user) != 0) {
                rc = SYNA_ERR_CANCELLED;
                break;
            }
            continue;
        }

        rc = enrollment_update_start(d, key, &key);
        if (rc != SYNA_OK) { enrollment_end(d); break; }

        rc = append_new_image(d, &template_, &tid, &progress);
        enrollment_end(d);
        if (rc != SYNA_OK)
            break;

        touches++;
        if (cb)
            cb(SYNA_ENROLL_PROGRESS, touches, progress, user);

        if (tid.len)
            break;                       /* the sensor says it has enough */
    }

    enrollment_end(d);
    syna_glow_end(d);

    if (rc != SYNA_OK)
        goto out;
    if (!tid.len) {
        rc = SYNA_ERR_PROTO;
        goto out;
    }

    /* Only now is anything written to the database. */
    rc = syna_db_lookup_user(d, storage, ident.p, ident.len, &userid);
    if (rc == SYNA_ERR_NOT_FOUND) {
        rc = syna_db_new_record(d, storage, 5, storage, ident.p, ident.len, &userid);
        if (rc != SYNA_OK)
            goto out;
        syna_dbg("created user record #%u for '%s'", userid, username);
    } else if (rc != SYNA_OK) {
        goto out;
    }

    if ((rc = make_finger_data(subtype, &template_, &tid, &finger)) != SYNA_OK)
        goto out;

    /* Asking for type 0xb yields a finger record (0x6); the write-enable blob
     * is what performs the substitution. */
    rc = syna_db_new_record(d, userid, 0xb, storage, finger.p, finger.len, &recid);
    if (rc != SYNA_OK)
        goto out;

    syna_wait_interrupt(d, ibuf, sizeof ibuf, &ilen, 3000);
    syna_dbg("stored finger record #%u under user #%u", recid, userid);
    rc = SYNA_OK;
out:
    syna_buf_free(&template_);
    syna_buf_free(&tid);
    syna_buf_free(&ident);
    syna_buf_free(&finger);
    return rc;
}

/* --------------------------------------------------------------------------
 * Verification
 *
 * Matching alone only says which record the finger belongs to. Verifying a
 * named user means resolving that user's record first and insisting the match
 * points at it - otherwise any enrolled finger would authenticate anyone.
 * ----------------------------------------------------------------------- */
int syna_verify(syna_dev *d, const char *username, syna_match_result *out)
{
    syna_buf ident = { 0 };
    syna_capture_result cr;
    uint16_t storage = 0, expected = 0;
    int rc;

    if (!d || !username || !out)
        return SYNA_ERR_INVAL;
    memset(out, 0, sizeof *out);

    if (!d->type_info && (rc = syna_sensor_setup(d)) != SYNA_OK)
        return rc;

    if ((rc = syna_identity_for_user(username, &ident)) != SYNA_OK)
        goto out;

    if ((rc = syna_db_user_storage(d, "StgWindsor", &storage)) != SYNA_OK)
        goto out;

    /* SYNA_ERR_NOT_FOUND here means this user has nothing enrolled, which the
     * caller should treat as "unavailable", not "rejected". */
    if ((rc = syna_db_lookup_user(d, storage, ident.p, ident.len, &expected)) != SYNA_OK)
        goto out;

    syna_glow_start(d);
    rc = syna_capture(d, SYNA_CAPTURE_IDENTIFY, &cr);
    if (rc != SYNA_OK) {
        syna_glow_end(d);
        goto out;
    }

    rc = syna_match(d, out);
    syna_glow_end(d);
    if (rc != SYNA_OK)
        goto out;

    if (out->matched && out->user_id != expected) {
        syna_dbg("finger belongs to record #%u, not #%u", out->user_id, expected);
        out->matched = 0;
    }
out:
    syna_buf_free(&ident);
    return rc;
}

/* Remove one enrolled finger, or all of them when subtype < 0. */
int syna_delete(syna_dev *d, const char *username, int subtype, int *removed)
{
    syna_buf ident = { 0 };
    syna_user_info info;
    uint16_t storage = 0, userid = 0;
    int rc, i, n = 0;

    if (!d || !username)
        return SYNA_ERR_INVAL;
    if (removed)
        *removed = 0;

    if ((rc = syna_identity_for_user(username, &ident)) != SYNA_OK)
        goto out;
    if ((rc = syna_db_user_storage(d, "StgWindsor", &storage)) != SYNA_OK)
        goto out;
    if ((rc = syna_db_lookup_user(d, storage, ident.p, ident.len, &userid)) != SYNA_OK)
        goto out;
    if ((rc = syna_db_get_user(d, userid, &info)) != SYNA_OK)
        goto out;

    for (i = 0; i < info.n_fingers; i++) {
        if (subtype >= 0 && info.fingers[i].subtype != (uint16_t)subtype)
            continue;
        rc = syna_db_del_record(d, info.fingers[i].dbid);
        if (rc != SYNA_OK) {
            syna_dbg("could not delete finger record #%u: %s",
                     info.fingers[i].dbid, syna_strerror(rc));
            goto out;
        }
        syna_dbg("deleted finger record #%u (%s)",
                 info.fingers[i].dbid, syna_subtype_name(info.fingers[i].subtype));
        n++;
    }

    /* A user record with no fingers left serves no purpose. */
    if (n && n == info.n_fingers) {
        rc = syna_db_del_record(d, userid);
        if (rc != SYNA_OK)
            syna_dbg("finger records gone but user #%u remains: %s",
                     userid, syna_strerror(rc));
        rc = SYNA_OK;
    }

    if (removed)
        *removed = n;
    rc = n ? SYNA_OK : SYNA_ERR_NOT_FOUND;
out:
    syna_buf_free(&ident);
    return rc;
}
