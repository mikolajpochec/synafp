/* synafp_vcsfw.c - the VCSFW command layer and flash access.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#define _POSIX_C_SOURCE 200809L
#include "synafp_priv.h"

#include <stdlib.h>
#include <string.h>

/* Write a command and read whatever comes back, with no interpretation. */
int syna_vcsfw_raw(syna_dev *d, const uint8_t *out, size_t outlen, syna_buf *reply)
{
    int rc, len = 0;

    rc = syna_bulk_out(d, out, (int)outlen, SYNA_CMD_TIMEOUT_MS);
    if (rc != SYNA_OK)
        return rc;

    rc = syna_bulk_in(d, d->rx, SYNA_RX_BUFFER, &len, SYNA_REPLY_TIMEOUT_MS);
    if (rc != SYNA_OK)
        return rc;

    reply->len = 0;
    return syna_buf_add(reply, d->rx, (size_t)len);
}

/* Handshake records travel inside command 0x44; application records do not. */
int syna_vcsfw_tls_xfer(syna_dev *d, const uint8_t *records, size_t len, syna_buf *reply)
{
    static const uint8_t hdr[4] = { VCSFW_CMD_TLS_DATA, 0, 0, 0 };
    syna_buf out = { 0 };
    int rc;

    if ((rc = syna_buf_add(&out, hdr, sizeof hdr)) != SYNA_OK) goto done;
    if ((rc = syna_buf_add(&out, records, len)) != SYNA_OK) goto done;
    rc = syna_vcsfw_raw(d, out.p, out.len, reply);
done:
    syna_buf_free(&out);
    return rc;
}

/* Issue a command, using the secure channel once it is up. */
int syna_vcsfw_cmd(syna_dev *d, const uint8_t *cmd, size_t len, syna_buf *reply)
{
    reply->len = 0;
    if (d->tls.secure_tx && d->tls.secure_rx)
        return syna_tls_cmd(d, cmd, len, reply);
    return syna_vcsfw_raw(d, cmd, len, reply);
}

/* Every reply starts with a little-endian status word. */
static int check_status(const syna_buf *reply)
{
    uint16_t status;

    if (reply->len < 2)
        return SYNA_ERR_PROTO;
    status = (uint16_t)(reply->p[0] | (reply->p[1] << 8));
    if (status != 0)
        return -(SYNA_ERR_SENSOR_BASE + status);
    return SYNA_OK;
}

int syna_vcsfw_call(syna_dev *d, const uint8_t *cmd, size_t len, syna_buf *reply)
{
    int rc = syna_vcsfw_cmd(d, cmd, len, reply);
    if (rc != SYNA_OK)
        return rc;
    return check_status(reply);
}

/* --------------------------------------------------------------------------
 * Flash
 * ----------------------------------------------------------------------- */
static void put_le16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void put_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;  p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static uint16_t get_le16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t get_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

int syna_read_flash(syna_dev *d, uint8_t partition, uint32_t addr, uint32_t size,
                    syna_buf *out)
{
    uint8_t cmd[13];
    syna_buf reply = { 0 };
    uint32_t got;
    int rc;

    cmd[0] = VCSFW_CMD_FLASH_READ;
    cmd[1] = partition;
    cmd[2] = 1;
    put_le16(cmd + 3, 0);
    put_le32(cmd + 5, addr);
    put_le32(cmd + 9, size);

    rc = syna_vcsfw_call(d, cmd, sizeof cmd, &reply);
    if (rc != SYNA_OK)
        goto done;

    if (reply.len < 8) {
        rc = SYNA_ERR_PROTO;
        goto done;
    }
    got = get_le32(reply.p + 2);
    if (got > reply.len - 8)
        got = (uint32_t)(reply.len - 8);

    out->len = 0;
    rc = syna_buf_add(out, reply.p + 8, got);
done:
    syna_buf_free(&reply);
    return rc;
}

int syna_flash_info_get(syna_dev *d, syna_flash_info *out)
{
    uint8_t cmd = VCSFW_CMD_FLASH_INFO;
    syna_buf reply = { 0 };
    const uint8_t *p;
    int rc, i, pcnt;

    if (!d || !out)
        return SYNA_ERR_INVAL;
    memset(out, 0, sizeof *out);

    rc = syna_vcsfw_call(d, &cmd, 1, &reply);
    if (rc != SYNA_OK)
        goto done;

    if (reply.len < 2 + 0xe) {
        rc = SYNA_ERR_PROTO;
        goto done;
    }
    p = reply.p + 2;
    out->jedec_id0 = get_le16(p + 0);
    out->jedec_id1 = get_le16(p + 2);
    out->blocks    = get_le16(p + 4);
    out->blocksize = get_le16(p + 8);
    pcnt           = get_le16(p + 12);

    p += 0xe;
    if (pcnt > (int)(sizeof out->partitions / sizeof out->partitions[0]))
        pcnt = (int)(sizeof out->partitions / sizeof out->partitions[0]);
    if (reply.len < 2u + 0xeu + (size_t)pcnt * 0xc) {
        rc = SYNA_ERR_PROTO;
        goto done;
    }

    for (i = 0; i < pcnt; i++) {
        const uint8_t *e = p + i * 0xc;
        out->partitions[i].id         = e[0];
        out->partitions[i].type       = e[1];
        out->partitions[i].access_lvl = get_le16(e + 2);
        out->partitions[i].offset     = get_le32(e + 4);
        out->partitions[i].size       = get_le32(e + 8);
    }
    out->n_partitions = pcnt;
    rc = SYNA_OK;
done:
    syna_buf_free(&reply);
    return rc;
}

/* --------------------------------------------------------------------------
 * Diagnostics: what is actually in the credential store?
 * ----------------------------------------------------------------------- */
int syna_creds_report(syna_dev *d, FILE *out)
{
    syna_buf flash = { 0 };
    const uint8_t *p;
    size_t len;
    int rc, hwkey;

    hwkey = (syna_tls_set_hwkey_from_dmi(&d->tls) == SYNA_OK);
    fprintf(out, "Host key      : %s\n",
            hwkey ? "derived from DMI identity"
                  : "unavailable (needs root to read the DMI serial)");

    rc = syna_read_flash(d, SYNA_TLS_PARTITION, 0, SYNA_TLS_FLASH_SIZE, &flash);
    if (rc != SYNA_OK)
        goto done;

    fprintf(out, "Credentials   : %zu bytes read from partition %d\n",
            flash.len, SYNA_TLS_PARTITION);

    p = flash.p;
    len = flash.len;
    while (len >= 4 + 32) {
        uint16_t id = (uint16_t)(p[0] | (p[1] << 8));
        uint16_t sz = (uint16_t)(p[2] | (p[3] << 8));
        const char *what;

        if (id == 0xffff)
            break;
        if (len < 4u + 32u + sz)
            break;

        switch (id) {
        case 0: case 1: case 2: what = "reserved"; break;
        case 3: what = "client certificate"; break;
        case 4: what = "client private key (encrypted to this host)"; break;
        case 5: what = "curve parameters"; break;
        case 6: what = "sensor ECDH key, signed by Synaptics"; break;
        default: what = "unknown"; break;
        }
        fprintf(out, "  block %-2u %6u bytes  %s\n", id, sz, what);

        p   += 4 + 32 + sz;
        len -= 4 + 32 + sz;
    }

    /* This validates every block hash, the Synaptics signature over the ECDH
     * parameters, and - when we have the host key - the private key itself. */
    rc = syna_tls_parse_flash(&d->tls, flash.p, flash.len);
    fprintf(out, "Validation    : %s\n",
            rc == SYNA_OK ? "all blocks verified" : syna_strerror(rc));
done:
    syna_buf_free(&flash);
    return rc;
}
