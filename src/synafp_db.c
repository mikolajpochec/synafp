/* synafp_db.c - the template database stored in the sensor's flash.
 *
 * Records form a tree: storages contain users, users contain fingers, and
 * fingers contain the template data blobs. Everything is addressed by a
 * 16-bit record id and reached over the secure channel.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#define _POSIX_C_SOURCE 200809L
#include "synafp_priv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

const char *syna_record_type_name(uint16_t type)
{
    switch (type) {
    case 1: return "root";
    case 2: return "storage";
    case 4: return "user storage";
    case 5: return "user";
    case 6: return "finger";
    case 8: return "data";
    }
    return "unknown";
}

const char *syna_subtype_name(uint16_t subtype)
{
    switch (subtype) {
    case 0xf5: return "right-thumb";
    case 0xf6: return "right-index";
    case 0xf7: return "right-middle";
    case 0xf8: return "right-ring";
    case 0xf9: return "right-little";
    case 0xfa: return "left-thumb";
    case 0xfb: return "left-index";
    case 0xfc: return "left-middle";
    case 0xfd: return "left-ring";
    case 0xfe: return "left-little";
    }
    return "unknown finger";
}

int syna_db_info(syna_dev *d, syna_db_info_t *out)
{
    uint8_t cmd = VCSFW_CMD_DB_INFO;
    syna_buf reply = { 0 };
    int rc, i;

    if (!d || !out)
        return SYNA_ERR_INVAL;
    memset(out, 0, sizeof *out);

    rc = syna_vcsfw_call(d, &cmd, 1, &reply);
    if (rc != SYNA_OK)
        goto done;
    if (reply.len < 2 + 0x18) {
        rc = SYNA_ERR_PROTO;
        goto done;
    }
    {
        const uint8_t *p = reply.p + 2;
        out->total   = rd32(p + 8);
        out->used    = rd32(p + 12);
        out->free    = rd32(p + 16);
        out->records = rd16(p + 20);
        out->n_roots = rd16(p + 22);
        if (out->n_roots > (int)(sizeof out->roots / sizeof out->roots[0]))
            out->n_roots = (int)(sizeof out->roots / sizeof out->roots[0]);
        if (reply.len < 2u + 0x18u + (size_t)out->n_roots * 2) {
            rc = SYNA_ERR_PROTO;
            goto done;
        }
        for (i = 0; i < out->n_roots; i++)
            out->roots[i] = rd16(p + 0x18 + i * 2);
    }
    rc = SYNA_OK;
done:
    syna_buf_free(&reply);
    return rc;
}

int syna_db_children(syna_dev *d, uint16_t dbid, syna_db_record *out)
{
    uint8_t cmd[3];
    syna_buf reply = { 0 };
    int rc, i, cnt;

    if (!d || !out)
        return SYNA_ERR_INVAL;
    memset(out, 0, sizeof *out);

    cmd[0] = VCSFW_CMD_DB_CHILDREN;
    cmd[1] = (uint8_t)dbid;
    cmd[2] = (uint8_t)(dbid >> 8);

    rc = syna_vcsfw_call(d, cmd, sizeof cmd, &reply);
    if (rc != SYNA_OK)
        goto done;
    if (reply.len < 14) {
        rc = SYNA_ERR_PROTO;
        goto done;
    }

    out->dbid    = rd16(reply.p + 2);
    out->type    = rd16(reply.p + 4);
    out->storage = rd16(reply.p + 6);
    cnt          = rd16(reply.p + 10);

    if (cnt > (int)(sizeof out->children / sizeof out->children[0]))
        cnt = (int)(sizeof out->children / sizeof out->children[0]);
    if (reply.len < 14u + (size_t)cnt * 4) {
        rc = SYNA_ERR_PROTO;
        goto done;
    }
    for (i = 0; i < cnt; i++) {
        out->children[i].dbid = rd16(reply.p + 14 + i * 4);
        out->children[i].type = rd16(reply.p + 16 + i * 4);
    }
    out->n_children = cnt;
    rc = SYNA_OK;
done:
    syna_buf_free(&reply);
    return rc;
}

int syna_db_value(syna_dev *d, uint16_t dbid, uint16_t *type, syna_buf *out)
{
    uint8_t cmd[3];
    syna_buf reply = { 0 };
    uint16_t sz;
    int rc;

    if (!d || !out)
        return SYNA_ERR_INVAL;

    cmd[0] = VCSFW_CMD_DB_VALUE;
    cmd[1] = (uint8_t)dbid;
    cmd[2] = (uint8_t)(dbid >> 8);

    rc = syna_vcsfw_call(d, cmd, sizeof cmd, &reply);
    if (rc != SYNA_OK)
        goto done;
    if (reply.len < 12) {
        rc = SYNA_ERR_PROTO;
        goto done;
    }
    if (type)
        *type = rd16(reply.p + 4);
    sz = rd16(reply.p + 8);
    if ((size_t)sz > reply.len - 12)
        sz = (uint16_t)(reply.len - 12);

    out->len = 0;
    rc = syna_buf_add(out, reply.p + 12, sz);
done:
    syna_buf_free(&reply);
    return rc;
}

/* Walk the record tree, printing what is stored. */
static int dump_record(syna_dev *d, uint16_t dbid, uint16_t type, int depth, FILE *out)
{
    syna_db_record rec;
    syna_buf val = { 0 };
    uint16_t vtype = 0;
    int i, rc;

    /* The parent's child list gives a type, but roots have none, so prefer
     * the type the record reports for itself. */
    rc = syna_db_children(d, dbid, &rec);
    if (rc == SYNA_OK && rec.type)
        type = rec.type;

    fprintf(out, "%*s#%-5u %-13s", depth * 2, "", dbid, syna_record_type_name(type));

    /* Users and storages carry a readable name; fingers carry a subtype. */
    if (syna_db_value(d, dbid, &vtype, &val) == SYNA_OK && val.len) {
        if (type == 4 || type == 2 || type == 1) {
            size_t n = val.len;
            while (n && val.p[n - 1] == '\0') n--;
            fprintf(out, " \"%.*s\"", (int)n, (const char *)val.p);
        } else if (type == 6 && val.len >= 2) {
            fprintf(out, " %s", syna_subtype_name(rd16(val.p)));
        } else {
            fprintf(out, " (%zu bytes)", val.len);
        }
    }
    fputc('\n', out);
    syna_buf_free(&val);

    if (rc != SYNA_OK)
        return SYNA_OK;   /* leaf, or not enumerable: not an error */

    for (i = 0; i < rec.n_children; i++)
        dump_record(d, rec.children[i].dbid, rec.children[i].type, depth + 1, out);
    return SYNA_OK;
}

int syna_db_dump(syna_dev *d, FILE *out)
{
    syna_db_info_t info;
    int rc, i;

    rc = syna_db_info(d, &info);
    if (rc != SYNA_OK)
        return rc;

    fprintf(out, "Database      : %u bytes total, %u used, %u free, %u records\n",
            info.total, info.used, info.free, info.records);

    for (i = 0; i < info.n_roots; i++)
        dump_record(d, info.roots[i], 1, 1, out);

    if (!info.n_roots)
        fprintf(out, "  (no records)\n");
    return SYNA_OK;
}
