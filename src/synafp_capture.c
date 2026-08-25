/* synafp_capture.c - building the capture program and running a scan.
 *
 * A capture is driven by a "program": a list of type/length/value chunks that
 * the firmware executes. A base program is stored per sensor type (see
 * synafp_tables.c) and must be patched before every scan - the timeslot table
 * is rewritten for the sensor geometry, and calibration values are spliced in.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#define _POSIX_C_SOURCE 200809L
#include "synafp_priv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

/* Vendor matching rules: an exact masked version wins; a zero mask or zero
 * version is only a fallback. */
const syna_dev_info *syna_dev_info_lookup(uint16_t major, uint16_t version)
{
    const syna_dev_info *fuzzy = NULL;
    int i;

    for (i = 0; i < syna_dev_info_table_len; i++) {
        const syna_dev_info *e = &syna_dev_info_table[i];
        uint8_t masked;

        if (e->major != major)
            continue;
        masked = (uint8_t)(e->version & e->version_mask);
        if (version == 0 || masked == 0)
            fuzzy = e;
        else if ((uint8_t)version == masked)
            return e;
    }
    return fuzzy;
}

const syna_type_info *syna_type_lookup(uint16_t sensor_type)
{
    int i;
    for (i = 0; i < syna_type_table_len; i++)
        if (syna_type_table[i].sensor_type == sensor_type)
            return &syna_type_table[i];
    return NULL;
}

/* --------------------------------------------------------------------------
 * Program chunks: [u16 type][u16 length][value]
 * ----------------------------------------------------------------------- */
typedef struct {
    uint16_t type;
    syna_buf data;
} syna_chunk;

typedef struct {
    syna_chunk *v;
    int         n, cap;
} syna_chunks;

static void chunks_free(syna_chunks *cs)
{
    int i;
    for (i = 0; i < cs->n; i++)
        syna_buf_free(&cs->v[i].data);
    free(cs->v);
    cs->v = NULL;
    cs->n = cs->cap = 0;
}

static syna_chunk *chunks_push(syna_chunks *cs, uint16_t type)
{
    if (cs->n == cs->cap) {
        int cap = cs->cap ? cs->cap * 2 : 16;
        syna_chunk *nv = realloc(cs->v, (size_t)cap * sizeof *nv);
        if (!nv)
            return NULL;
        cs->v = nv;
        cs->cap = cap;
    }
    memset(&cs->v[cs->n], 0, sizeof cs->v[cs->n]);
    cs->v[cs->n].type = type;
    return &cs->v[cs->n++];
}

static int chunks_split(syna_chunks *cs, const uint8_t *p, size_t len)
{
    while (len >= 4) {
        uint16_t type = (uint16_t)(p[0] | (p[1] << 8));
        uint16_t sz   = (uint16_t)(p[2] | (p[3] << 8));
        syna_chunk *c;

        if ((size_t)sz > len - 4)
            return SYNA_ERR_PROTO;
        c = chunks_push(cs, type);
        if (!c)
            return SYNA_ERR_NOMEM;
        if (syna_buf_add(&c->data, p + 4, sz) != SYNA_OK)
            return SYNA_ERR_NOMEM;

        p   += 4 + sz;
        len -= 4 + sz;
    }
    return SYNA_OK;
}

static int chunks_merge(const syna_chunks *cs, syna_buf *out)
{
    int i, rc;

    for (i = 0; i < cs->n; i++) {
        uint8_t hdr[4];
        size_t n = cs->v[i].data.len;

        hdr[0] = (uint8_t)cs->v[i].type;
        hdr[1] = (uint8_t)(cs->v[i].type >> 8);
        hdr[2] = (uint8_t)n;
        hdr[3] = (uint8_t)(n >> 8);
        if ((rc = syna_buf_add(out, hdr, 4)) != SYNA_OK) return rc;
        if ((rc = syna_buf_add(out, cs->v[i].data.p, n)) != SYNA_OK) return rc;
    }
    return SYNA_OK;
}

/* --------------------------------------------------------------------------
 * The timeslot instruction set
 * ----------------------------------------------------------------------- */
typedef struct {
    int op, size;
    uint32_t a, b, c;
} syna_insn;

static int decode_insn(const uint8_t *p, size_t len, syna_insn *o)
{
    uint8_t v;

    if (len < 1)
        return SYNA_ERR_PROTO;
    v = p[0];
    memset(o, 0, sizeof *o);

    if (v <= 4) {
        o->op = v; o->size = 1;
    } else if (v == 5 || v == 6) {
        o->op = v; o->size = 2;
        if (len < 2) return SYNA_ERR_PROTO;
        o->a = p[1];
    } else if (v == 7) {
        o->op = 7; o->size = 2;
        if (len < 2) return SYNA_ERR_PROTO;
        o->a = p[1] ? p[1] : 0x100;
    } else if ((v & 0xfe) == 0x08) {
        o->op = 8; o->size = 2;
        if (len < 2) return SYNA_ERR_PROTO;
        o->a = (uint32_t)((v & 1) << 8) | p[1];
    } else if ((v & 0xfe) == 0x0a) {
        o->op = 9; o->size = 2;
        if (len < 2) return SYNA_ERR_PROTO;
        o->a = (uint32_t)((v & 1) << 8) | p[1];
    } else if ((v & 0xfc) == 0x0c) {
        o->op = 10; o->size = 1; o->a = v & 3;
    } else if ((v & 0xf8) == 0x10) {
        o->op = 11; o->size = 3;
        if (len < 3) return SYNA_ERR_PROTO;
        o->a = v & 7;
        o->b = (uint32_t)p[1] << 2;
        o->c = p[2] ? p[2] : 0x100;
    } else if ((v & 0xe0) == 0x20) {
        o->op = 12; o->size = 1; o->a = v & 0x1f;
    } else if ((v & 0xc0) == 0x40) {
        o->op = 13; o->size = 3;
        if (len < 3) return SYNA_ERR_PROTO;
        o->a = (uint32_t)(v & 0x3f) * 4 + 0x80002000u;
        o->b = (uint32_t)p[1] | ((uint32_t)p[2] << 8);
    } else if ((v & 0xc0) == 0x80) {
        o->op = 14; o->size = 1;
        o->a = (uint32_t)(v & 0x38) >> 3;
        o->b = v & 7;
    } else {                                   /* (v & 0xc0) == 0xc0 */
        o->op = 15; o->size = 2;
        if (len < 2) return SYNA_ERR_PROTO;
        o->a = (uint32_t)(v & 0x38) >> 3;
        o->b = v & 7;
        o->c = p[1] ? p[1] : 0x100;
    }
    return SYNA_OK;
}

/* Offset of the nth instruction with the given opcode, or -1. */
static long find_nth_insn(const uint8_t *b, size_t len, int opcode, int n)
{
    size_t pc = 0;

    while (pc < len) {
        syna_insn in;
        if (decode_insn(b + pc, len - pc, &in) != SYNA_OK)
            return -1;
        if (in.op == opcode && --n == 0)
            return (long)pc;
        pc += (size_t)in.size;
    }
    return -1;
}

static long find_nth_regwrite(const uint8_t *b, size_t len, uint32_t reg, int n)
{
    size_t pc = 0;

    while (pc < len) {
        syna_insn in;
        if (decode_insn(b + pc, len - pc, &in) != SYNA_OK)
            return -1;
        if (in.op == 13 && in.a == reg && --n == 0)
            return (long)pc;
        pc += (size_t)in.size;
    }
    return -1;
}

/* Scale the sample repeat counts for this sensor's line multiplier. */
static void patch_timeslot_table(uint8_t *b, size_t len, int inc_address, int mult)
{
    size_t i = 0;

    while (i + 3 < len) {
        if ((b[i] & 0xf8) == 0x10) {
            if (b[i + 2] > 1) {
                b[i + 2] = (uint8_t)(b[i + 2] * mult);
                if (inc_address)
                    b[i + 1] = (uint8_t)(b[i + 1] + 1);
            }
            i += 3;
            continue;
        }
        if (b[i] == 0) { i += 1; continue; }
        if (b[i] == 7) { i += 2; continue; }
        break;
    }
}

/* Take the gain for the middle of the sensor from the factory table. */
static void patch_timeslot_again(syna_dev *d, uint8_t *b, size_t len)
{
    size_t pc = 0;
    long target = -1, match = -1;

    while (pc < len) {
        syna_insn in;
        if (decode_insn(b + pc, len - pc, &in) != SYNA_OK)
            return;
        if (in.op == 1 || in.op == 2 || in.op == 4)
            break;
        if (in.op == 11)
            target = (long)in.b;               /* call destination */
        pc += (size_t)in.size;
    }
    if (target < 0 || (size_t)target >= len)
        return;

    pc = (size_t)target;
    while (pc < len) {
        syna_insn in;
        if (decode_insn(b + pc, len - pc, &in) != SYNA_OK)
            return;
        if (in.op == 1 || in.op == 2 || in.op == 4)
            break;
        if (in.op == 13 && in.a == 0x8000203cu)
            match = (long)pc;
        pc += (size_t)in.size;
    }
    if (match < 0 || (size_t)match + 1 >= len)
        return;
    if ((size_t)d->key_calibration_line >= d->factory_calib.len)
        return;

    b[match + 1] = d->factory_calib.p[d->key_calibration_line];
}

/* --------------------------------------------------------------------------
 * Calibration helpers
 * ----------------------------------------------------------------------- */
static int get_key_line(syna_dev *d, syna_buf *out)
{
    const syna_type_info *ti = d->type_info;
    int width = ti->line_width;
    int i;

    out->len = 0;

    if (d->calib_data.len > 0) {
        size_t per_line = d->calib_data.len / (size_t)ti->lines_per_calibration_data;
        size_t off = 8 + per_line * (size_t)d->key_calibration_line;

        if (off + (size_t)width > d->calib_data.len)
            return SYNA_ERR_PROTO;
        if (syna_buf_add(out, d->calib_data.p + off, (size_t)width) != SYNA_OK)
            return SYNA_ERR_NOMEM;
        for (i = 0; i < width; i++)
            if (out->p[i] == 5)
                out->p[i] = 4;
        return SYNA_OK;
    }

    for (i = 0; i < width; i++)
        if (syna_buf_add(out, "\0", 1) != SYNA_OK)
            return SYNA_ERR_NOMEM;
    return SYNA_OK;
}

/* Pack values as a dense little-endian bit stream of u bits each, biased by
 * the minimum. Returns the bit width and the bias. */
static int bitpack(const uint8_t *b, size_t n, uint8_t *u_out, uint8_t *m_out,
                   syna_buf *out)
{
    unsigned mn = 255, mx = 0, u = 0, span;
    size_t i, nbytes;
    uint8_t *acc;

    if (!n)
        return SYNA_ERR_INVAL;
    for (i = 0; i < n; i++) {
        if (b[i] < mn) mn = b[i];
        if (b[i] > mx) mx = b[i];
    }
    span = mx - mn;
    while (span) { span >>= 1; u++; }

    nbytes = (u * n + 7) / 8;
    acc = calloc(nbytes ? nbytes : 1, 1);
    if (!acc)
        return SYNA_ERR_NOMEM;

    for (i = 0; i < n; i++) {
        unsigned v = (unsigned)(b[i] - mn) & ((u >= 8) ? 0xffu : ((1u << u) - 1));
        size_t bit = i * u, k;
        for (k = 0; k < u; k++) {
            if (v & (1u << k))
                acc[(bit + k) / 8] |= (uint8_t)(1u << ((bit + k) % 8));
        }
    }

    out->len = 0;
    if (syna_buf_add(out, acc, nbytes) != SYNA_OK) {
        free(acc);
        return SYNA_ERR_NOMEM;
    }
    free(acc);
    *u_out = (uint8_t)u;
    *m_out = (uint8_t)mn;
    return SYNA_OK;
}

/* --------------------------------------------------------------------------
 * Line update - splices calibration into the program
 * ----------------------------------------------------------------------- */
typedef struct {
    uint32_t mask, flags;
    uint8_t  v0, v1;
    uint16_t v2;
    syna_buf data;
} syna_line;

static void put32(syna_buf *b, uint32_t v)
{
    uint8_t t[4] = { (uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24) };
    syna_buf_add(b, t, 4);
}

static int line_update_type_1(syna_dev *d, syna_capture_mode mode, syna_chunks *cs)
{
    static const uint8_t wtf_identify[40] = {
        0xfb, 0xb2, 0x0f, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x30, 0x00, 0x00, 0x00,
        0x87, 0x00, 0x02, 0x00, 0x67, 0x00, 0x0a, 0x00, 0x01, 0x80, 0x00, 0x00,
        0x0a, 0x02, 0x00, 0x00, 0x0b, 0x19, 0x00, 0x00, 0x88, 0x13, 0xb8, 0x0b,
        0x01, 0x09, 0x10, 0x00,
    };
    static const uint8_t recon_identify[28] = {
        0x02, 0x00, 0x18, 0x00, 0x02, 0x00, 0x00, 0x00, 0x70, 0x00, 0x70, 0x00,
        0x4d, 0x01, 0x00, 0x00, 0xa0, 0x00, 0x8c, 0x00, 0x3c, 0x32, 0x32, 0x1e,
        0x3c, 0x0a, 0x02, 0x02,
    };
    static const uint8_t fd_enroll[40] = {
        0xfb, 0xb2, 0x0f, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x30, 0x00, 0x00, 0x00,
        0x87, 0x00, 0x02, 0x00, 0x67, 0x00, 0x0a, 0x00, 0x01, 0x80, 0x00, 0x00,
        0x0a, 0x02, 0x00, 0x00, 0x0b, 0x19, 0x00, 0x00, 0x50, 0xc3, 0x60, 0xea,
        0x01, 0x09, 0x10, 0x00,
    };
    static const uint8_t recon_enroll[28] = {
        0x02, 0x00, 0x18, 0x00, 0x23, 0x00, 0x00, 0x00, 0x70, 0x00, 0x70, 0x00,
        0x4d, 0x01, 0x00, 0x00, 0xa0, 0x00, 0x8c, 0x00, 0x3c, 0x32, 0x32, 0x1e,
        0x3c, 0x0a, 0x02, 0x02,
    };

    const syna_type_info *ti = d->type_info;
    syna_line *lines = NULL;
    int n_lines = 0, cap_lines = 0, i, rc = SYNA_ERR_NOMEM;
    syna_buf tst = { 0 }, key = { 0 }, packed = { 0 }, lu = { 0 }, tr = { 0 };
    syna_chunk *c;
    long pc;
    uint32_t cnt = 2;

    /* Rewrite the 2D timeslot table for this sensor's geometry. */
    for (i = 0; i < cs->n; i++) {
        if (cs->v[i].type != 0x34)
            continue;

        tst.len = 0;
        if (syna_buf_add(&tst, cs->v[i].data.p, cs->v[i].data.len) != SYNA_OK) goto out;
        patch_timeslot_table(tst.p, tst.len, 1, ti->repeat_multiplier);
        if (mode != SYNA_CAPTURE_CALIBRATE)
            patch_timeslot_again(d, tst.p, tst.len);

        if ((rc = get_key_line(d, &key)) != SYNA_OK) goto out;
        cs->v[i].data.len = 0;
        if (syna_buf_add(&cs->v[i].data, key.p, key.len) != SYNA_OK) goto out;
        if (tst.len > (size_t)ti->line_width)
            if (syna_buf_add(&cs->v[i].data, tst.p + ti->line_width,
                             tst.len - (size_t)ti->line_width) != SYNA_OK) goto out;
    }
    if (!tst.len) {
        syna_dbg("capture program has no 2D timeslot table");
        rc = SYNA_ERR_PROTO;
        goto out;
    }

    if (!(c = chunks_push(cs, 0x17))) goto out;   /* reply configuration */

    if (mode == SYNA_CAPTURE_IDENTIFY) {
        if (!(c = chunks_push(cs, 0x4e))) goto out;
        if (syna_buf_add(&c->data, wtf_identify, sizeof wtf_identify) != SYNA_OK) goto out;
        if (!(c = chunks_push(cs, 0x2e))) goto out;
        if (syna_buf_add(&c->data, recon_identify, sizeof recon_identify) != SYNA_OK) goto out;
    } else if (mode == SYNA_CAPTURE_ENROLL) {
        if (!(c = chunks_push(cs, 0x26))) goto out;
        if (syna_buf_add(&c->data, fd_enroll, sizeof fd_enroll) != SYNA_OK) goto out;
        if (!(c = chunks_push(cs, 0x2e))) goto out;
        if (syna_buf_add(&c->data, recon_enroll, sizeof recon_enroll) != SYNA_OK) goto out;
    }

    if (!(c = chunks_push(cs, 0x44))) goto out;   /* interleave */
    put32(&c->data, 1);

    /* Line 1: the per-type calibration blob, anchored at the 2nd "Enable Rx". */
    cap_lines = 4 + 112;
    lines = calloc((size_t)cap_lines, sizeof *lines);
    if (!lines) goto out;

    pc = find_nth_insn(tst.p, tst.len, 6, 2);
    if (pc < 0) { rc = SYNA_ERR_PROTO; goto out; }
    lines[n_lines].mask  = 0xff;
    lines[n_lines].flags = (uint32_t)(pc + 1) | (cnt << 20) | 0x7000000u;
    lines[n_lines].v0    = 0x0f;
    if (syna_buf_add(&lines[n_lines].data, ti->calib_blob, ti->calib_blob_len) != SYNA_OK) goto out;
    n_lines++;
    cnt++;

    /* Line 2: factory gain values, anchored at the first write to 0x8000203C. */
    pc = find_nth_regwrite(tst.p, tst.len, 0x8000203cu, 1);
    if (pc < 0) { rc = SYNA_ERR_PROTO; goto out; }
    {
        uint8_t u = 0, m = 0;
        if ((rc = bitpack(d->factory_calib.p, d->factory_calib.len, &u, &m, &packed)) != SYNA_OK)
            goto out;
        lines[n_lines].mask  = 0xff;
        lines[n_lines].flags = (uint32_t)(pc + 1) | (cnt << 20) | 0x7000000u;
        lines[n_lines].v0    = (uint8_t)((u - 1) | 8);
        lines[n_lines].v1    = m;
        if (syna_buf_add(&lines[n_lines].data, packed.p, packed.len) != SYNA_OK) goto out;
        n_lines++;
        cnt++;
    }

    /* Remaining lines carry the per-line calibration, when we have it. */
    if (d->calib_data.len > 0) {
        size_t per_line = d->calib_data.len / (size_t)ti->lines_per_calibration_data;
        int off, j;

        for (off = 0; off < 112; off += 4) {
            syna_line *l = &lines[n_lines];
            l->mask  = 0xffffffffu;
            l->flags = (uint32_t)off | (0x85u << 24);
            for (j = 0; j < 112; j++) {
                size_t p = 8 + (size_t)j * per_line + (size_t)off;
                if (p + 4 > d->calib_data.len) { rc = SYNA_ERR_PROTO; goto out; }
                if (syna_buf_add(&l->data, d->calib_data.p + p, 4) != SYNA_OK) goto out;
            }
            n_lines++;
        }
    }

    /* The sensor requires each blob to be dword aligned. */
    for (i = 0; i < n_lines; i++) {
        size_t pad = lines[i].data.len % 4;
        if (pad)
            if (syna_buf_add(&lines[i].data, "\0\0\0", 4 - pad) != SYNA_OK) goto out;
    }

    put32(&lu, (uint32_t)n_lines);
    for (i = 0; i < n_lines; i++) {
        put32(&lu, lines[i].mask);
        put32(&lu, lines[i].flags);
    }
    for (i = 0; i < n_lines; i++)
        if (((lines[i].flags & 0x00f00000u) >> 20) <= 1)
            if (syna_buf_add(&lu, lines[i].data.p, lines[i].data.len) != SYNA_OK) goto out;

    if (!(c = chunks_push(cs, 0x30))) goto out;
    if (syna_buf_add(&c->data, lu.p, lu.len) != SYNA_OK) goto out;

    for (i = 0; i < n_lines; i++) {
        if (((lines[i].flags & 0x00f00000u) >> 20) > 1) {
            uint8_t hdr[4];
            hdr[0] = lines[i].v0;
            hdr[1] = lines[i].v1;
            hdr[2] = (uint8_t)lines[i].v2;
            hdr[3] = (uint8_t)(lines[i].v2 >> 8);
            if (syna_buf_add(&tr, hdr, 4) != SYNA_OK) goto out;
            if (syna_buf_add(&tr, lines[i].data.p, lines[i].data.len) != SYNA_OK) goto out;
        }
    }
    if (!(c = chunks_push(cs, 0x43))) goto out;
    if (syna_buf_add(&c->data, tr.p, tr.len) != SYNA_OK) goto out;

    rc = SYNA_OK;
out:
    if (lines) {
        for (i = 0; i < cap_lines; i++)
            syna_buf_free(&lines[i].data);
        free(lines);
    }
    syna_buf_free(&tst);
    syna_buf_free(&key);
    syna_buf_free(&packed);
    syna_buf_free(&lu);
    syna_buf_free(&tr);
    return rc;
}

int syna_build_capture_program(syna_dev *d, syna_capture_mode mode, syna_buf *out)
{
    syna_chunks cs = { 0 };
    const syna_type_info *ti = d->type_info;
    uint8_t hdr[5];
    uint16_t req_lines = 0;
    int rc;

    if ((rc = chunks_split(&cs, ti->prog, ti->prog_len)) != SYNA_OK) goto out;
    if (ti->line_update_type != 1) {
        /* Only the type 1 variant is implemented; the table records which a
         * sensor needs so an unsupported one fails cleanly. */
        syna_dbg("sensor type 0x%04x needs line update variant %d",
                 ti->sensor_type, ti->line_update_type);
        rc = SYNA_ERR_UNSUPPORTED;
        goto out;
    }
    if ((rc = line_update_type_1(d, mode, &cs)) != SYNA_OK) goto out;

    if (mode == SYNA_CAPTURE_CALIBRATE)
        req_lines = (uint16_t)(ti->calibration_frames * d->lines_per_frame + 1);

    hdr[0] = 2;
    hdr[1] = (uint8_t)ti->bytes_per_line;
    hdr[2] = (uint8_t)(ti->bytes_per_line >> 8);
    hdr[3] = (uint8_t)req_lines;
    hdr[4] = (uint8_t)(req_lines >> 8);

    out->len = 0;
    if ((rc = syna_buf_add(out, hdr, sizeof hdr)) != SYNA_OK) goto out;
    rc = chunks_merge(&cs, out);
out:
    chunks_free(&cs);
    return rc;
}

/* --------------------------------------------------------------------------
 * Sensor setup
 * ----------------------------------------------------------------------- */
static int get_factory_bits(syna_dev *d, uint16_t tag, uint16_t want_subtag, syna_buf *out)
{
    uint8_t cmd[9];
    syna_buf reply = { 0 };
    const uint8_t *p;
    size_t len;
    uint32_t entries, i;
    int rc, found = 0;

    cmd[0] = VCSFW_CMD_FACTORY_BITS;
    cmd[1] = (uint8_t)tag;
    cmd[2] = (uint8_t)(tag >> 8);
    cmd[3] = 0; cmd[4] = 0;
    cmd[5] = 0; cmd[6] = 0; cmd[7] = 0; cmd[8] = 0;

    rc = syna_vcsfw_call(d, cmd, sizeof cmd, &reply);
    if (rc != SYNA_OK)
        goto done;
    if (reply.len < 2 + 8) { rc = SYNA_ERR_PROTO; goto done; }

    p = reply.p + 2;
    len = reply.len - 2;
    entries = (uint32_t)p[4] | ((uint32_t)p[5] << 8) |
              ((uint32_t)p[6] << 16) | ((uint32_t)p[7] << 24);
    p += 8;
    len -= 8;

    for (i = 0; i < entries; i++) {
        uint16_t l, subtag;

        if (len < 12) { rc = SYNA_ERR_PROTO; goto done; }
        l      = (uint16_t)(p[4] | (p[5] << 8));
        subtag = (uint16_t)(p[8] | (p[9] << 8));
        p += 12;
        len -= 12;
        if (len < l) { rc = SYNA_ERR_PROTO; goto done; }

        if (subtag == want_subtag) {
            out->len = 0;
            /* the first four bytes are a header we do not need */
            if (l > 4)
                if ((rc = syna_buf_add(out, p + 4, (size_t)l - 4)) != SYNA_OK) goto done;
            found = 1;
        }
        p += l;
        len -= l;
    }
    rc = found ? SYNA_OK : SYNA_ERR_PROTO;
done:
    syna_buf_free(&reply);
    return rc;
}

int syna_sensor_setup(syna_dev *d)
{
    const syna_dev_info *info;
    uint16_t major = 0, minor = 0;
    int rc;

    if (!syna_has_session(d))
        return SYNA_ERR_PROTO;

    rc = syna_identify_sensor(d, &major, &minor);
    if (rc != SYNA_OK)
        return rc;

    info = syna_dev_info_lookup(major, minor);
    if (!info) {
        syna_dbg("unrecognised sensor: major 0x%04x version 0x%04x", major, minor);
        return SYNA_ERR_UNSUPPORTED;
    }
    d->sensor_type = info->type;
    d->model_name = info->name;
    syna_dbg("sensor model '%s', type 0x%04x", info->name, info->type);

    d->type_info = syna_type_lookup(d->sensor_type);
    if (!d->type_info) {
        syna_dbg("no capture tables for sensor type 0x%04x ('%s')",
                 d->sensor_type, info->name);
        return SYNA_ERR_UNSUPPORTED;
    }

    d->key_calibration_line = d->type_info->key_calibration_line;
    d->lines_per_frame = 0;

    if (!d->calib_data.len &&
        syna_load_calibration(d, SYNA_CALIB_DEFAULT_PATH) != SYNA_OK)
        syna_dbg("no calibration data at %s", SYNA_CALIB_DEFAULT_PATH);

    rc = get_factory_bits(d, 0x0e00, 3, &d->factory_calib);
    if (rc != SYNA_OK) {
        syna_dbg("cannot read factory calibration values: %s", syna_strerror(rc));
        return rc;
    }
    syna_dbg("sensor type 0x%04x, %zu factory calibration values",
             d->sensor_type, d->factory_calib.len);
    return SYNA_OK;
}

/* --------------------------------------------------------------------------
 * Interrupts and the capture state machine
 * ----------------------------------------------------------------------- */
int syna_interrupt_read(syna_dev *d, uint8_t *buf, int cap, int *len, unsigned timeout_ms)
{
    int transferred = 0, e;

    e = libusb_interrupt_transfer(d->h, SYNA_EP_INTERRUPT, buf, cap,
                                  &transferred, timeout_ms);
    if (e != 0)
        return syna_usb_error(e);
    *len = transferred;
    syna_hexdump("INT", buf, transferred);
    return SYNA_OK;
}

/* Poll until an interrupt arrives, honouring cancellation. */
int syna_wait_interrupt(syna_dev *d, uint8_t *buf, int cap, int *len, unsigned overall_ms)
{
    unsigned waited = 0;

    for (;;) {
        int rc = syna_interrupt_read(d, buf, cap, len, 200);

        if (rc == SYNA_OK)
            return SYNA_OK;
        if (rc != SYNA_ERR_TIMEOUT)
            return rc;
        if (d->cancel_req)
            return SYNA_ERR_CANCELLED;

        waited += 200;
        if (overall_ms && waited >= overall_ms)
            return SYNA_ERR_TIMEOUT;
    }
}

int syna_glow_start(syna_dev *d)
{
    static const uint8_t cmd[125] = {
        0x39, 0x20, 0xbf, 0x02, 0x00, 0xff, 0xff, 0x00, 0x00, 0x01, 0x99, 0x00,
        0x20, 0x00, 0x00, 0x00, 0x00, 0x99, 0x99, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00,
        0x00, 0x00, 0x99, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
    };
    syna_buf r = { 0 };
    int rc = syna_vcsfw_call(d, cmd, sizeof cmd, &r);
    syna_buf_free(&r);
    return rc;
}

int syna_glow_end(syna_dev *d)
{
    static const uint8_t cmd[125] = {
        0x39, 0xf4, 0x01, 0x00, 0x00, 0xf4, 0x01, 0x00, 0x00, 0x01, 0xff, 0x00,
        0x20, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf4, 0x01, 0x00,
        0x00, 0x00, 0xff, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
    };
    syna_buf r = { 0 };
    int rc = syna_vcsfw_call(d, cmd, sizeof cmd, &r);
    syna_buf_free(&r);
    return rc;
}

int syna_capture(syna_dev *d, syna_capture_mode mode, syna_capture_result *out)
{
    static const uint8_t stop[] = { 0x04 };
    static const uint8_t status2[] = { 0x51, 0x00, 0x20, 0x00, 0x00 };
    syna_buf cmd = { 0 }, reply = { 0 };
    uint8_t ibuf[64];
    int ilen = 0, rc;

    if (!d->type_info && (rc = syna_sensor_setup(d)) != SYNA_OK)
        return rc;

    rc = syna_build_capture_program(d, mode, &cmd);
    if (rc != SYNA_OK)
        goto out;
    syna_dbg("capture program is %zu bytes", cmd.len);

    rc = syna_vcsfw_call(d, cmd.p, cmd.len, &reply);
    if (rc != SYNA_OK)
        goto out;

    /* start */
    rc = syna_wait_interrupt(d, ibuf, sizeof ibuf, &ilen, 5000);
    if (rc != SYNA_OK) goto stop_out;
    if (ilen < 1 || ibuf[0] != 0) {
        syna_dbg("unexpected interrupt at start: 0x%02x", ilen ? ibuf[0] : 0);
        rc = SYNA_ERR_PROTO;
        goto stop_out;
    }

    /* wait for a finger */
    for (;;) {
        rc = syna_wait_interrupt(d, ibuf, sizeof ibuf, &ilen, d->op_timeout_ms);
        if (rc != SYNA_OK) goto stop_out;
        if (ilen >= 1 && ibuf[0] == 2)
            break;
    }

    /* wait for the scan to complete */
    for (;;) {
        rc = syna_wait_interrupt(d, ibuf, sizeof ibuf, &ilen, 10000);
        if (rc != SYNA_OK) goto stop_out;
        if (ilen < 3 || ibuf[0] != 3) {
            rc = SYNA_ERR_PROTO;
            goto stop_out;
        }
        if (ibuf[2] & 4)
            break;
    }

    rc = syna_vcsfw_call(d, status2, sizeof status2, &reply);
    if (rc != SYNA_OK) goto stop_out;

    if (reply.len < 2 + 4 + 12) { rc = SYNA_ERR_PROTO; goto stop_out; }
    {
        const uint8_t *p = reply.p + 6;
        uint32_t err;
        if (out) {
            out->x  = (uint16_t)(p[0] | (p[1] << 8));
            out->y  = (uint16_t)(p[2] | (p[3] << 8));
            out->w1 = (uint16_t)(p[4] | (p[5] << 8));
            out->w2 = (uint16_t)(p[6] | (p[7] << 8));
        }
        err = (uint32_t)p[8] | ((uint32_t)p[9] << 8) |
              ((uint32_t)p[10] << 16) | ((uint32_t)p[11] << 24);
        if (err != 0) {
            syna_dbg("scan reported error 0x%08x", err);
            rc = -(SYNA_ERR_SENSOR_BASE + (int)(err & 0xffff));
            goto stop_out;
        }
    }
    rc = SYNA_OK;

stop_out:
    {
        syna_buf r = { 0 };
        syna_vcsfw_cmd(d, stop, sizeof stop, &r);
        syna_buf_free(&r);
    }
out:
    syna_buf_free(&cmd);
    syna_buf_free(&reply);
    return rc;
}

/* Print the program we would send, plus the inputs it was built from, so it
 * can be diffed against a known-good implementation. Sends nothing. */
int syna_dump_capture_program(syna_dev *d, syna_capture_mode mode, FILE *out)
{
    syna_buf prog = { 0 };
    size_t i;
    int rc;

    if (!d->type_info && (rc = syna_sensor_setup(d)) != SYNA_OK)
        return rc;

    fprintf(out, "sensor_type=%04x\n", d->sensor_type);
    fprintf(out, "factory_calib=");
    for (i = 0; i < d->factory_calib.len; i++)
        fprintf(out, "%02x", d->factory_calib.p[i]);
    fprintf(out, "\n");
    fprintf(out, "calib_data_len=%zu\n", d->calib_data.len);

    rc = syna_build_capture_program(d, mode, &prog);
    if (rc != SYNA_OK) {
        syna_buf_free(&prog);
        return rc;
    }
    fprintf(out, "program=");
    for (i = 0; i < prog.len; i++)
        fprintf(out, "%02x", prog.p[i]);
    fprintf(out, "\n");
    syna_buf_free(&prog);
    return SYNA_OK;
}

/* --------------------------------------------------------------------------
 * Matching
 *
 * After a successful capture the image sits in the sensor. 0x5e asks it to
 * match that image against the on-flash template database, 0x60 collects the
 * verdict, and 0x62 releases the result. The verdict is a TLV dictionary:
 * [u16 tag][u16 length][value].
 * ----------------------------------------------------------------------- */
const uint8_t *syna_dict_get(const uint8_t *p, size_t len, uint16_t tag, uint16_t *out_len)
{
    while (len >= 4) {
        uint16_t t = (uint16_t)(p[0] | (p[1] << 8));
        uint16_t l = (uint16_t)(p[2] | (p[3] << 8));

        if ((size_t)l > len - 4)
            return NULL;
        if (t == tag) {
            *out_len = l;
            return p + 4;
        }
        p   += 4 + l;
        len -= 4 + l;
    }
    return NULL;
}

int syna_match(syna_dev *d, syna_match_result *out)
{
    static const uint8_t start[]   = { 0x5e, 0x02, 0xff,
                                       0x00, 0x00,   /* storage id: any */
                                       0x00, 0x00,   /* user id: any    */
                                       0x01, 0x00,
                                       0x00, 0x00,
                                       0x00, 0x00 };
    static const uint8_t results[] = { 0x60, 0x00, 0x00, 0x00, 0x00 };
    static const uint8_t release[] = { 0x62, 0x00, 0x00, 0x00, 0x00 };

    syna_buf reply = { 0 };
    uint8_t ibuf[64];
    int ilen = 0, rc;

    if (!d || !out)
        return SYNA_ERR_INVAL;
    memset(out, 0, sizeof *out);

    rc = syna_vcsfw_call(d, start, sizeof start, &reply);
    if (rc != SYNA_OK)
        goto done;

    rc = syna_wait_interrupt(d, ibuf, sizeof ibuf, &ilen, 10000);
    if (rc != SYNA_OK)
        goto done;

    if (ilen < 1 || ibuf[0] != 3) {
        /* The sensor says it could not place this finger. That is a normal
         * outcome, not a failure of the driver. */
        syna_dbg("no match (interrupt type 0x%02x)", ilen ? ibuf[0] : 0);
        out->matched = 0;
        rc = SYNA_OK;
        goto done;
    }

    rc = syna_vcsfw_call(d, results, sizeof results, &reply);
    if (rc != SYNA_OK)
        goto done;

    if (reply.len < 4) {
        rc = SYNA_ERR_PROTO;
        goto done;
    }
    {
        const uint8_t *body = reply.p + 4;
        size_t blen = reply.len - 4;
        uint16_t declared = (uint16_t)(reply.p[2] | (reply.p[3] << 8));
        const uint8_t *v;
        uint16_t vlen;

        if (declared != blen) {
            syna_dbg("match result length mismatch: %u declared, %zu present",
                     declared, blen);
            rc = SYNA_ERR_PROTO;
            goto done;
        }

        v = syna_dict_get(body, blen, 1, &vlen);
        if (v && vlen >= 4)
            out->user_id = (uint32_t)v[0] | ((uint32_t)v[1] << 8) |
                           ((uint32_t)v[2] << 16) | ((uint32_t)v[3] << 24);

        v = syna_dict_get(body, blen, 3, &vlen);
        if (v && vlen >= 2)
            out->subtype = (uint16_t)(v[0] | (v[1] << 8));

        v = syna_dict_get(body, blen, 4, &vlen);
        if (v && vlen == sizeof out->hash) {
            memcpy(out->hash, v, sizeof out->hash);
            out->have_hash = 1;
        }
        out->matched = 1;
    }
    rc = SYNA_OK;
done:
    {
        syna_buf r = { 0 };
        syna_vcsfw_cmd(d, release, sizeof release, &r);
        syna_buf_free(&r);
    }
    syna_buf_free(&reply);
    return rc;
}

/* --------------------------------------------------------------------------
 * Calibration data
 *
 * Per-line calibration is host-side state: the sensor keeps a reference image
 * in flash, but the per-line correction table lives here. Without it the key
 * line is written as zeros and finger detection does not work.
 * ----------------------------------------------------------------------- */
int syna_load_calibration(syna_dev *d, const char *path)
{
    FILE *f;
    long n;
    uint8_t *buf;
    int rc;

    if (!d || !path)
        return SYNA_ERR_INVAL;

    f = fopen(path, "rb");
    if (!f)
        return SYNA_ERR_NOT_FOUND;

    if (fseek(f, 0, SEEK_END) != 0 || (n = ftell(f)) <= 0 || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return SYNA_ERR_PROTO;
    }

    buf = malloc((size_t)n);
    if (!buf) {
        fclose(f);
        return SYNA_ERR_NOMEM;
    }
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) {
        free(buf);
        fclose(f);
        return SYNA_ERR_PROTO;
    }
    fclose(f);

    d->calib_data.len = 0;
    rc = syna_buf_add(&d->calib_data, buf, (size_t)n);
    free(buf);
    if (rc != SYNA_OK)
        return rc;

    syna_dbg("loaded %ld bytes of calibration data from %s", n, path);
    return SYNA_OK;
}

int syna_save_calibration(syna_dev *d, const char *path)
{
    FILE *f;
    char dir[512];
    char *slash;

    if (!d || !path || !d->calib_data.len)
        return SYNA_ERR_INVAL;

    /* Create the containing directory if we can; fopen reports the real
     * problem if this is not enough. */
    snprintf(dir, sizeof dir, "%s", path);
    slash = strrchr(dir, '/');
    if (slash && slash != dir) {
        *slash = '\0';
        mkdir(dir, 0755);
    }

    f = fopen(path, "wb");
    if (!f)
        return SYNA_ERR_ACCESS;
    if (fwrite(d->calib_data.p, 1, d->calib_data.len, f) != d->calib_data.len) {
        fclose(f);
        return SYNA_ERR_PROTO;
    }
    fclose(f);
    return SYNA_OK;
}

int syna_have_calibration(const syna_dev *d)
{
    return d && d->calib_data.len > 0;
}
