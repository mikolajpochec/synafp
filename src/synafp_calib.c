/* synafp_calib.c - generating per-line calibration data.
 *
 * The sensor needs two calibration artefacts before it will read a finger:
 *
 *   - a per-line correction table, which is host state (calib-data.bin);
 *   - a reference "clean slate" image, stored in flash partition 6.
 *
 * Both are produced here by capturing blank frames, averaging the interleaved
 * lines, and folding the result into a running correction table. The maths is
 * reproduced from the vendor driver, including its quirks: the first frame is
 * discarded, only the first eight bytes of each line are left untouched, and
 * the scale factor is a fixed ratio rather than anything derived.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#define _POSIX_C_SOURCE 200809L
#include "synafp_priv.h"

#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Clamp to a signed byte, returned in unsigned form. */
static uint8_t clip(int x)
{
    if (x < -128) x = -128;
    if (x > 127)  x = 127;
    return (uint8_t)(x & 0xff);
}

/* The scale factor is hardcoded per device in the vendor driver. */
static uint8_t scale_sample(uint8_t v)
{
    int x = (int)v - 0x80;
    x = x * 10 / 0x22;
    return clip(x);
}

static uint8_t add_signed(uint8_t l, uint8_t r)
{
    return clip((int)(int8_t)l + (int)(int8_t)r);
}

/* The number of lines per frame is carried in the capture program itself, in
 * the "2D" chunk. */
int syna_compute_lines_per_frame(syna_dev *d)
{
    const syna_type_info *ti = d->type_info;
    const uint8_t *p = ti->prog;
    size_t len = ti->prog_len;

    while (len >= 4) {
        uint16_t type = (uint16_t)(p[0] | (p[1] << 8));
        uint16_t sz   = (uint16_t)(p[2] | (p[3] << 8));

        if ((size_t)sz > len - 4)
            break;
        if (type == 0x2f && sz >= 4) {
            uint32_t lines_2d = (uint32_t)p[4] | ((uint32_t)p[5] << 8) |
                                ((uint32_t)p[6] << 16) | ((uint32_t)p[7] << 24);
            d->lines_per_frame = (int)lines_2d * ti->repeat_multiplier;
            syna_dbg("lines per frame: %d", d->lines_per_frame);
            return SYNA_OK;
        }
        p   += 4 + sz;
        len -= 4 + sz;
    }
    syna_dbg("capture program has no 2D chunk");
    return SYNA_ERR_PROTO;
}

/* Reduce the captured frames to one frame of calibration lines. */
static int average_frames(syna_dev *d, const syna_buf *raw, syna_buf *out)
{
    const syna_type_info *ti = d->type_info;
    size_t bpl = (size_t)ti->bytes_per_line;
    size_t frame_size = (size_t)d->lines_per_frame * bpl;
    int interleave = d->lines_per_frame / ti->lines_per_calibration_data;
    int input_frames = ti->calibration_frames;
    size_t base = 0;

    if (frame_size == 0 || interleave < 1)
        return SYNA_ERR_PROTO;

    out->len = 0;

    if (interleave > 1) {
        size_t group = (size_t)interleave * bpl;
        size_t off;

        /* The first frame is discarded: it is captured before the analogue
         * front end has settled. */
        if (input_frames > 1)
            base = frame_size;
        if (raw->len < base + frame_size) {
            syna_dbg("short calibration capture: %zu bytes, need %zu",
                     raw->len, base + frame_size);
            return SYNA_ERR_PROTO;
        }

        for (off = 0; off + bpl <= frame_size; off += group) {
            size_t avail = frame_size - off;
            size_t lines = (avail < group ? avail : group) / bpl;
            size_t i, j;

            if (!lines)
                break;
            for (i = 0; i < bpl; i++) {
                unsigned sum = 0;
                for (j = 0; j < lines; j++)
                    sum += raw->p[base + off + j * bpl + i];
                {
                    uint8_t v = (uint8_t)(sum / lines);
                    if (syna_buf_add(out, &v, 1) != SYNA_OK)
                        return SYNA_ERR_NOMEM;
                }
            }
        }
    } else {
        size_t i, f;

        if (input_frames > 1) {
            input_frames -= 2;
            base = frame_size * 2;
        }
        if (input_frames < 1)
            input_frames = 1;
        if (raw->len < base + frame_size * (size_t)input_frames)
            return SYNA_ERR_PROTO;

        for (i = 0; i < frame_size; i++) {
            unsigned sum = 0;
            for (f = 0; f < (size_t)input_frames; f++)
                sum += raw->p[base + f * frame_size + i];
            {
                uint8_t v = (uint8_t)(sum / (unsigned)input_frames);
                if (syna_buf_add(out, &v, 1) != SYNA_OK)
                    return SYNA_ERR_NOMEM;
            }
        }
    }
    return SYNA_OK;
}

/* Scale one captured frame and fold it into the running table. */
static int process_calibration_results(syna_dev *d, const syna_buf *cooked)
{
    size_t bpl = (size_t)d->type_info->bytes_per_line;
    syna_buf scaled = { 0 };
    size_t off, i;
    int rc = SYNA_OK;

    for (off = 0; off + bpl <= cooked->len; off += bpl) {
        /* The first eight bytes of a line are header, not samples. */
        if ((rc = syna_buf_add(&scaled, cooked->p + off, 8)) != SYNA_OK) goto out;
        for (i = 8; i < bpl; i++) {
            uint8_t v = scale_sample(cooked->p[off + i]);
            if ((rc = syna_buf_add(&scaled, &v, 1)) != SYNA_OK) goto out;
        }
    }

    if (d->calib_data.len == 0) {
        d->calib_data.len = 0;
        rc = syna_buf_add(&d->calib_data, scaled.p, scaled.len);
        goto out;
    }

    /* Later runs accumulate: header preserved, samples summed as signed. */
    {
        size_t n = d->calib_data.len < scaled.len ? d->calib_data.len : scaled.len;
        for (off = 0; off + bpl <= n; off += bpl)
            for (i = 8; i < bpl; i++)
                d->calib_data.p[off + i] =
                    add_signed(d->calib_data.p[off + i], scaled.p[off + i]);
    }
out:
    syna_buf_free(&scaled);
    return rc;
}

/* One blank capture, returned already averaged. */
static int capture_blank(syna_dev *d, syna_buf *out)
{
    syna_buf prog = { 0 }, reply = { 0 }, raw = { 0 };
    int rc;

    rc = syna_build_capture_program(d, SYNA_CAPTURE_CALIBRATE, &prog);
    if (rc != SYNA_OK)
        goto done;

    rc = syna_vcsfw_call(d, prog.p, prog.len, &reply);
    if (rc != SYNA_OK)
        goto done;

    rc = syna_read_image(d, &raw, 10000);
    if (rc != SYNA_OK)
        goto done;

    rc = average_frames(d, &raw, out);
done:
    syna_buf_free(&prog);
    syna_buf_free(&reply);
    syna_buf_free(&raw);
    return rc;
}

/* Wrap the reference image the way the firmware expects to find it. */
static int build_clean_slate(const syna_buf *img, syna_buf *out)
{
    syna_buf inner = { 0 };
    uint8_t hdr[4], digest[32];
    static const uint8_t zeros[32] = { 0 };
    int rc;

    /* inner = [u16 len][image][u16 0] */
    hdr[0] = (uint8_t)img->len;
    hdr[1] = (uint8_t)(img->len >> 8);
    if ((rc = syna_buf_add(&inner, hdr, 2)) != SYNA_OK) goto out;
    if ((rc = syna_buf_add(&inner, img->p, img->len)) != SYNA_OK) goto out;
    hdr[0] = 0; hdr[1] = 0;
    if ((rc = syna_buf_add(&inner, hdr, 2)) != SYNA_OK) goto out;

    SHA256(inner.p, inner.len, digest);

    /* out = [u16 magic][u16 len][sha256][32 zeros][inner] */
    out->len = 0;
    hdr[0] = 0x02; hdr[1] = 0x50;
    hdr[2] = (uint8_t)inner.len;
    hdr[3] = (uint8_t)(inner.len >> 8);
    if ((rc = syna_buf_add(out, hdr, 4)) != SYNA_OK) goto out;
    if ((rc = syna_buf_add(out, digest, sizeof digest)) != SYNA_OK) goto out;
    if ((rc = syna_buf_add(out, zeros, sizeof zeros)) != SYNA_OK) goto out;
    rc = syna_buf_add(out, inner.p, inner.len);
out:
    syna_buf_free(&inner);
    return rc;
}

static int persist_clean_slate(syna_dev *d, const syna_buf *cs)
{
    syna_buf head = { 0 };
    int rc, blank = 1, i;

    rc = syna_read_flash(d, 6, 0, 0x44, &head);
    if (rc != SYNA_OK)
        goto done;

    for (i = 0; i < (int)head.len; i++)
        if (head.p[i] != 0xff) { blank = 0; break; }

    if (!blank) {
        if (head.len >= 0x44 && cs->len >= 0x44 &&
            memcmp(cs->p, head.p, 0x44) == 0) {
            syna_dbg("flash already holds this reference image");
            rc = SYNA_OK;
            goto done;
        }
        syna_dbg("erasing calibration partition");
        rc = syna_erase_flash(d, 6);
        if (rc != SYNA_OK)
            goto done;
    }

    rc = syna_write_flash_all(d, 6, 0, cs->p, cs->len);
done:
    syna_buf_free(&head);
    return rc;
}

int syna_calibrate(syna_dev *d, syna_calib_cb cb, void *user)
{
    syna_buf cooked = { 0 }, cs = { 0 }, blob = { 0 };
    int rc, i, iters;

    if (!d)
        return SYNA_ERR_INVAL;
    if (!d->type_info && (rc = syna_sensor_setup(d)) != SYNA_OK)
        return rc;
    if (!d->lines_per_frame && (rc = syna_compute_lines_per_frame(d)) != SYNA_OK)
        return rc;

    /* Start from scratch: accumulating onto an existing table would be wrong. */
    d->calib_data.len = 0;

    iters = d->type_info->calibration_iterations;
    for (i = 0; i < iters; i++) {
        if (cb && cb(i + 1, iters + 1, user) != 0) {
            rc = SYNA_ERR_CANCELLED;
            goto out;
        }
        if ((rc = capture_blank(d, &cooked)) != SYNA_OK)
            goto out;
        if ((rc = process_calibration_results(d, &cooked)) != SYNA_OK)
            goto out;
    }

    /* A final blank frame becomes the reference image kept in flash. */
    if (cb && cb(iters + 1, iters + 1, user) != 0) {
        rc = SYNA_ERR_CANCELLED;
        goto out;
    }
    if ((rc = capture_blank(d, &cs)) != SYNA_OK)
        goto out;
    if ((rc = build_clean_slate(&cs, &blob)) != SYNA_OK)
        goto out;

    syna_dbg("reference image %zu bytes, correction table %zu bytes",
             blob.len, d->calib_data.len);

    rc = persist_clean_slate(d, &blob);
out:
    syna_buf_free(&cooked);
    syna_buf_free(&cs);
    syna_buf_free(&blob);
    return rc;
}
