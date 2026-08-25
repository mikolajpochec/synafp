/* synafp_tls.c - the sensor's bespoke TLS 1.2 channel.
 *
 * Validity/Synaptics VCSFW sensors refuse almost every command outside an
 * encrypted session. The session is TLS 1.2 in shape but not in detail, so a
 * stock TLS library cannot be pointed at it:
 *
 *   - the cipher suite is 0xC005 (ECDH-ECDSA-AES256-CBC-SHA), with an ECDSA
 *     client certificate and a static server ECDH key;
 *   - records are MAC-then-encrypt with HMAC-SHA256 and AES-256-CBC;
 *   - several length fields are simply wrong with respect to RFC 5246, and
 *     have to be reproduced wrongly to interoperate;
 *   - the whole exchange is tunnelled inside VCSFW command 0x44.
 *
 * The client credentials are not stored on this computer. They live in the
 * sensor's own flash (partition 1, which is readable without a session), with
 * the private key encrypted under a key derived from this machine's DMI
 * product name and serial. That is what binds a paired sensor to one laptop.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#define _POSIX_C_SOURCE 200809L
#define OPENSSL_SUPPRESS_DEPRECATED
#include "synafp_priv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

/* Constants lifted from the Windows driver; they are the same on every unit. */
static const uint8_t password_hardcoded[32] = {
    0x71,0x7c,0xd7,0x2d,0x09,0x62,0xbc,0x4a,0x28,0x46,0x13,0x8d,0xbb,0x2c,0x24,0x19,
    0x25,0x12,0xa7,0x64,0x07,0x06,0x5f,0x38,0x38,0x46,0x13,0x9d,0x4b,0xec,0x20,0x33
};
static const uint8_t gwk_sign_hardcoded[32] = {
    0x3a,0x4c,0x76,0xb7,0x6a,0x97,0x98,0x1d,0x12,0x74,0x24,0x7e,0x16,0x66,0x10,0xe7,
    0x7f,0x4d,0x9c,0x9d,0x07,0xd3,0xc7,0x28,0xe5,0x32,0x91,0x6b,0xdd,0x28,0xb4,0x54
};

/* Synaptics' firmware signing key. The matching private key should only exist
 * inside a genuine sensor, so verifying against it proves the ECDH parameters
 * we just read out of flash were put there by real Synaptics firmware. */
static const char fwpub_x[] =
    "f727653b4e16ce0665a6894d7f3a30d7d0a0be310d1292a743671fdf69f6a8d3";
static const char fwpub_y[] =
    "a85538f8b6bec50d6eef8bd5f4d07a886243c58b2393948df761a84721a6ca94";

/* --------------------------------------------------------------------------
 * Small growable buffer
 * ----------------------------------------------------------------------- */
void syna_buf_free(syna_buf *b)
{
    free(b->p);
    b->p = NULL;
    b->len = b->cap = 0;
}

int syna_buf_add(syna_buf *b, const void *data, size_t n)
{
    if (b->len + n > b->cap) {
        size_t cap = b->cap ? b->cap : 256;
        uint8_t *np;
        while (cap < b->len + n)
            cap *= 2;
        np = realloc(b->p, cap);
        if (!np)
            return SYNA_ERR_NOMEM;
        b->p = np;
        b->cap = cap;
    }
    if (n)
        memcpy(b->p + b->len, data, n);
    b->len += n;
    return SYNA_OK;
}

static int buf_u8(syna_buf *b, uint8_t v)  { return syna_buf_add(b, &v, 1); }
static int buf_be16(syna_buf *b, uint16_t v)
{
    uint8_t t[2] = { (uint8_t)(v >> 8), (uint8_t)v };
    return syna_buf_add(b, t, 2);
}

/* --------------------------------------------------------------------------
 * TLS PRF (P_SHA256)
 * ----------------------------------------------------------------------- */
static void prf(const uint8_t *secret, size_t secret_len,
                const uint8_t *seed, size_t seed_len,
                uint8_t *out, size_t out_len)
{
    uint8_t a[32], block[32];
    unsigned int mac_len;
    size_t done = 0;
    uint8_t *tmp;

    HMAC(EVP_sha256(), secret, (int)secret_len, seed, seed_len, a, &mac_len);

    tmp = malloc(32 + seed_len);
    if (!tmp)
        return;

    while (done < out_len) {
        size_t take;

        memcpy(tmp, a, 32);
        memcpy(tmp + 32, seed, seed_len);
        HMAC(EVP_sha256(), secret, (int)secret_len, tmp, 32 + seed_len, block, &mac_len);

        take = out_len - done;
        if (take > 32)
            take = 32;
        memcpy(out + done, block, take);
        done += take;

        HMAC(EVP_sha256(), secret, (int)secret_len, a, 32, a, &mac_len);
    }
    free(tmp);
}

/* --------------------------------------------------------------------------
 * Host binding: derive the pre-TLS keys from this machine's identity
 * ----------------------------------------------------------------------- */
static int read_dmi(const char *name, char *out, size_t cap)
{
    char path[128];
    FILE *f;
    size_t n;

    snprintf(path, sizeof path, "/sys/class/dmi/id/%s", name);
    f = fopen(path, "r");
    if (!f)
        return SYNA_ERR_ACCESS;
    if (!fgets(out, (int)cap, f)) {
        fclose(f);
        return SYNA_ERR_ACCESS;
    }
    fclose(f);
    n = strlen(out);
    while (n && (out[n - 1] == '\n' || out[n - 1] == '\r' || out[n - 1] == ' '))
        out[--n] = '\0';
    return SYNA_OK;
}

int syna_tls_set_hwkey(syna_tls *t, const char *product_name, const char *serial)
{
    syna_buf seed = { 0 };
    uint8_t hw[512];
    size_t hwlen = 0;
    int rc;

    /* hw_key = "<product_name>\0<serial>\0" */
    hwlen = (size_t)snprintf((char *)hw, sizeof hw, "%s", product_name) + 1;
    if (hwlen >= sizeof hw)
        return SYNA_ERR_INVAL;
    hwlen += (size_t)snprintf((char *)hw + hwlen, sizeof hw - hwlen, "%s", serial) + 1;
    if (hwlen > sizeof hw)
        return SYNA_ERR_INVAL;

    if ((rc = syna_buf_add(&seed, "GWK", 3)) != SYNA_OK) goto out;
    if ((rc = syna_buf_add(&seed, hw, hwlen)) != SYNA_OK) goto out;
    prf(password_hardcoded, sizeof password_hardcoded,
        seed.p, seed.len, t->psk_encryption_key, 32);

    seed.len = 0;
    if ((rc = syna_buf_add(&seed, "GWK_SIGN", 8)) != SYNA_OK) goto out;
    if ((rc = syna_buf_add(&seed, gwk_sign_hardcoded, sizeof gwk_sign_hardcoded)) != SYNA_OK) goto out;
    prf(t->psk_encryption_key, 32, seed.p, seed.len, t->psk_validation_key, 32);
    t->have_hwkey = 1;

    rc = SYNA_OK;
out:
    syna_buf_free(&seed);
    return rc;
}

int syna_tls_set_hwkey_from_dmi(syna_tls *t)
{
    char name[256] = "", serial[256] = "";
    int rc;

    rc = read_dmi("product_name", name, sizeof name);
    if (rc != SYNA_OK) {
        syna_dbg("cannot read DMI product_name");
        return rc;
    }
    rc = read_dmi("product_serial", serial, sizeof serial);
    if (rc != SYNA_OK) {
        /* product_serial is mode 0400: this is the usual "not root" failure. */
        syna_dbg("cannot read DMI product_serial (needs root)");
        return SYNA_ERR_ACCESS;
    }

    syna_dbg("host binding: product_name='%s' serial='%s'", name, serial);
    return syna_tls_set_hwkey(t, name, serial);
}

/* --------------------------------------------------------------------------
 * Credentials stored in the sensor's flash
 *
 * Layout is a sequence of blocks:
 *   [u16 id][u16 size][sha256 of body][body]
 * terminated by id 0xffff. We need id 3 (our certificate), id 6 (the sensor's
 * static ECDH key, signed by Synaptics) and id 4 (our encrypted private key).
 * ----------------------------------------------------------------------- */
static EC_KEY *ec_pub_from_le(const uint8_t *x_le, const uint8_t *y_le)
{
    uint8_t xb[32], yb[32];
    EC_KEY *k = NULL;
    BIGNUM *x = NULL, *y = NULL;
    int i;

    for (i = 0; i < 32; i++) {
        xb[i] = x_le[31 - i];
        yb[i] = y_le[31 - i];
    }
    x = BN_bin2bn(xb, 32, NULL);
    y = BN_bin2bn(yb, 32, NULL);
    k = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!k || !x || !y)
        goto fail;
    /* Fails unless the point is actually on the curve. */
    if (EC_KEY_set_public_key_affine_coordinates(k, x, y) != 1)
        goto fail;
    BN_free(x); BN_free(y);
    return k;
fail:
    if (k) EC_KEY_free(k);
    BN_free(x); BN_free(y);
    return NULL;
}

static int verify_ecdh_signature(const uint8_t *key, size_t key_len,
                                 const uint8_t *sig, size_t sig_len)
{
    EC_KEY *fwpub = NULL;
    BIGNUM *x = NULL, *y = NULL;
    uint8_t digest[32];
    int ok = 0;

    BN_hex2bn(&x, fwpub_x);
    BN_hex2bn(&y, fwpub_y);
    fwpub = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!fwpub || !x || !y)
        goto out;
    if (EC_KEY_set_public_key_affine_coordinates(fwpub, x, y) != 1)
        goto out;

    SHA256(key, key_len, digest);
    ok = (ECDSA_verify(0, digest, sizeof digest, sig, (int)sig_len, fwpub) == 1);
out:
    if (fwpub) EC_KEY_free(fwpub);
    BN_free(x); BN_free(y);
    return ok;
}

static int handle_ecdh_block(syna_tls *t, const uint8_t *body, size_t len)
{
    uint32_t siglen;

    if (len < 0x90 + 4)
        return SYNA_ERR_PROTO;

    /* The x and y coordinates sit at fixed offsets inside a larger structure. */
    t->ecdh_q = ec_pub_from_le(body + 0x08, body + 0x4c);
    if (!t->ecdh_q) {
        syna_dbg("sensor ECDH point is not on P-256");
        return SYNA_ERR_PROTO;
    }

    siglen = (uint32_t)body[0x90] | ((uint32_t)body[0x91] << 8) |
             ((uint32_t)body[0x92] << 16) | ((uint32_t)body[0x93] << 24);
    if (0x94 + siglen > len)
        return SYNA_ERR_PROTO;

    if (!verify_ecdh_signature(body, 0x90, body + 0x94, siglen)) {
        syna_dbg("ECDH parameters are not signed by Synaptics");
        return SYNA_ERR_PROTO;
    }
    syna_dbg("sensor ECDH key verified against the Synaptics firmware key");
    return SYNA_OK;
}

static int handle_priv_block(syna_tls *t, const uint8_t *body, size_t len)
{
    uint8_t mac[32], *plain = NULL;
    unsigned int maclen;
    const uint8_t *c;
    size_t clen;
    EVP_CIPHER_CTX *ctx = NULL;
    int outl = 0, tmpl = 0, rc = SYNA_ERR_PROTO;
    BIGNUM *d = NULL;
    uint8_t d_be[32];
    int i, padlen;

    if (len < 1 + 16 + 32)
        return SYNA_ERR_PROTO;
    if (body[0] != 2) {
        syna_dbg("unknown private key blob prefix 0x%02x", body[0]);
        return SYNA_ERR_PROTO;
    }

    c = body + 1;
    clen = len - 1 - 32;

    HMAC(EVP_sha256(), t->psk_validation_key, 32, c, clen, mac, &maclen);
    if (memcmp(mac, c + clen, 32) != 0) {
        /* The key derives from this machine's DMI identity, so a mismatch
         * means the sensor is paired to a different computer. */
        syna_dbg("private key blob MAC mismatch");
        return SYNA_ERR_PAIRING;
    }

    plain = malloc(clen);
    if (!plain)
        return SYNA_ERR_NOMEM;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { rc = SYNA_ERR_NOMEM; goto out; }
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL,
                           t->psk_encryption_key, c) != 1) goto out;
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    if (EVP_DecryptUpdate(ctx, plain, &outl, c + 16, (int)(clen - 16)) != 1) goto out;
    if (EVP_DecryptFinal_ex(ctx, plain + outl, &tmpl) != 1) goto out;
    outl += tmpl;

    if (outl < 0x60 + 1) goto out;
    padlen = plain[outl - 1];              /* standard PKCS-style padding here */
    if (padlen <= 0 || padlen > outl) goto out;
    outl -= padlen;
    if (outl < 0x60) goto out;

    /* plaintext is x || y || d, each 32 bytes little-endian */
    for (i = 0; i < 32; i++)
        d_be[i] = plain[0x40 + 31 - i];

    d = BN_bin2bn(d_be, 32, NULL);
    if (!d) { rc = SYNA_ERR_NOMEM; goto out; }

    t->priv_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!t->priv_key) { rc = SYNA_ERR_NOMEM; goto out; }
    if (EC_KEY_set_private_key(t->priv_key, d) != 1) goto out;

    /* Some Windows driver versions leave x and y zeroed, so recompute the
     * public half from d rather than trusting what is stored. */
    {
        const EC_GROUP *g = EC_KEY_get0_group(t->priv_key);
        EC_POINT *pub = EC_POINT_new(g);
        if (!pub) { rc = SYNA_ERR_NOMEM; goto out; }
        if (EC_POINT_mul(g, pub, d, NULL, NULL, NULL) != 1) {
            EC_POINT_free(pub);
            goto out;
        }
        EC_KEY_set_public_key(t->priv_key, pub);
        EC_POINT_free(pub);
    }

    syna_dbg("client private key recovered from flash");
    rc = SYNA_OK;
out:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (d) BN_free(d);
    if (plain) { OPENSSL_cleanse(plain, clen); free(plain); }
    return rc;
}

int syna_tls_parse_flash(syna_tls *t, const uint8_t *p, size_t len)
{
    int rc;

    while (len >= 4 + 32) {
        uint16_t id, sz;
        uint8_t digest[32];
        const uint8_t *hash, *body;

        id = (uint16_t)(p[0] | (p[1] << 8));
        sz = (uint16_t)(p[2] | (p[3] << 8));
        if (id == 0xffff)
            break;

        hash = p + 4;
        body = p + 4 + 32;
        if (len < 4u + 32u + sz)
            return SYNA_ERR_PROTO;

        SHA256(body, sz, digest);
        if (memcmp(digest, hash, 32) != 0) {
            syna_dbg("flash block %04x fails its hash", id);
            return SYNA_ERR_PROTO;
        }
        syna_dbg("flash block id %04x (%u bytes)", id, sz);

        switch (id) {
        case 3:
            free(t->cert);
            t->cert = malloc(sz ? sz : 1);
            if (!t->cert)
                return SYNA_ERR_NOMEM;
            memcpy(t->cert, body, sz);
            t->cert_len = sz;
            break;
        case 4:
            /* Without the DMI-derived key we cannot decrypt this, but the rest
             * of the store is still worth validating. */
            if (!t->have_hwkey) {
                syna_dbg("skipping private key block (no host key)");
                break;
            }
            if ((rc = handle_priv_block(t, body, sz)) != SYNA_OK)
                return rc;
            break;
        case 6:
            if ((rc = handle_ecdh_block(t, body, sz)) != SYNA_OK)
                return rc;
            break;
        default:
            break;
        }

        p   += 4 + 32 + sz;
        len -= 4 + 32 + sz;
    }

    if (!t->cert || !t->ecdh_q || (t->have_hwkey && !t->priv_key)) {
        syna_dbg("flash is missing TLS credentials (cert=%d priv=%d ecdh=%d)",
                 !!t->cert, !!t->priv_key, !!t->ecdh_q);
        return SYNA_ERR_PAIRING;
    }
    return SYNA_OK;
}

/* --------------------------------------------------------------------------
 * Record protection
 * ----------------------------------------------------------------------- */
static void mac_header(uint8_t *hdr, uint8_t type, size_t len)
{
    hdr[0] = type;
    hdr[1] = 3;
    hdr[2] = 3;
    hdr[3] = (uint8_t)(len >> 8);
    hdr[4] = (uint8_t)len;
}

/* Append HMAC over (header || plaintext), MAC-then-encrypt style. */
static int tls_sign(syna_tls *t, uint8_t type, syna_buf *b)
{
    uint8_t hdr[5], mac[32];
    unsigned int maclen;
    HMAC_CTX *ctx = HMAC_CTX_new();

    if (!ctx)
        return SYNA_ERR_NOMEM;
    mac_header(hdr, type, b->len);
    HMAC_Init_ex(ctx, t->sign_key, 32, EVP_sha256(), NULL);
    HMAC_Update(ctx, hdr, 5);
    HMAC_Update(ctx, b->p, b->len);
    HMAC_Final(ctx, mac, &maclen);
    HMAC_CTX_free(ctx);

    return syna_buf_add(b, mac, 32);
}

static int tls_validate(syna_tls *t, uint8_t type, uint8_t *p, size_t *len)
{
    uint8_t hdr[5], mac[32];
    unsigned int maclen;
    size_t body;
    HMAC_CTX *ctx;

    if (*len < 32)
        return SYNA_ERR_PROTO;
    body = *len - 32;

    ctx = HMAC_CTX_new();
    if (!ctx)
        return SYNA_ERR_NOMEM;
    mac_header(hdr, type, body);
    HMAC_Init_ex(ctx, t->validation_key, 32, EVP_sha256(), NULL);
    HMAC_Update(ctx, hdr, 5);
    HMAC_Update(ctx, p, body);
    HMAC_Final(ctx, mac, &maclen);
    HMAC_CTX_free(ctx);

    if (memcmp(mac, p + body, 32) != 0) {
        syna_dbg("record MAC check failed");
        return SYNA_ERR_PROTO;
    }
    *len = body;
    return SYNA_OK;
}

/* AES-256-CBC with a random IV prepended. Padding is TLS style: the pad byte
 * value is (length - 1), repeated (length) times. */
static int tls_encrypt(syna_tls *t, const uint8_t *in, size_t inlen, syna_buf *out)
{
    uint8_t iv[16];
    size_t padlen = 16 - (inlen % 16);
    uint8_t *buf;
    EVP_CIPHER_CTX *ctx;
    int outl = 0, tmpl = 0, rc = SYNA_ERR_PROTO;

    if (RAND_bytes(iv, sizeof iv) != 1)
        return SYNA_ERR_PROTO;

    buf = malloc(inlen + padlen + 16);
    if (!buf)
        return SYNA_ERR_NOMEM;
    memcpy(buf, in, inlen);
    memset(buf + inlen, (int)(padlen - 1), padlen);

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { free(buf); return SYNA_ERR_NOMEM; }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, t->encryption_key, iv) != 1) goto out;
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    if (EVP_EncryptUpdate(ctx, buf, &outl, buf, (int)(inlen + padlen)) != 1) goto out;
    if (EVP_EncryptFinal_ex(ctx, buf + outl, &tmpl) != 1) goto out;
    outl += tmpl;

    if (syna_buf_add(out, iv, 16) != SYNA_OK) { rc = SYNA_ERR_NOMEM; goto out; }
    if (syna_buf_add(out, buf, (size_t)outl) != SYNA_OK) { rc = SYNA_ERR_NOMEM; goto out; }
    rc = SYNA_OK;
out:
    EVP_CIPHER_CTX_free(ctx);
    free(buf);
    return rc;
}

static int tls_decrypt(syna_tls *t, const uint8_t *in, size_t inlen,
                       uint8_t *out, size_t *outlen)
{
    EVP_CIPHER_CTX *ctx;
    int outl = 0, tmpl = 0, rc = SYNA_ERR_PROTO;
    size_t n;

    if (inlen < 32 || ((inlen - 16) % 16) != 0)
        return SYNA_ERR_PROTO;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return SYNA_ERR_NOMEM;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, t->decryption_key, in) != 1) goto out;
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    if (EVP_DecryptUpdate(ctx, out, &outl, in + 16, (int)(inlen - 16)) != 1) goto out;
    if (EVP_DecryptFinal_ex(ctx, out + outl, &tmpl) != 1) goto out;
    outl += tmpl;

    if (outl < 1) goto out;
    n = (size_t)outl;
    /* unpad: trailing byte holds (padlen - 1) */
    if ((size_t)out[n - 1] + 1 > n) goto out;
    n -= (size_t)out[n - 1] + 1;
    *outlen = n;
    rc = SYNA_OK;
out:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

/* --------------------------------------------------------------------------
 * Handshake construction
 *
 * Every handshake message is accumulated verbatim so the running transcript
 * hash can be recomputed on demand.
 * ----------------------------------------------------------------------- */
static int neg_add(syna_tls *t, syna_buf *out, uint8_t type,
                   const uint8_t *body, size_t len)
{
    uint8_t hdr[4];
    int rc;

    hdr[0] = type;
    hdr[1] = (uint8_t)(len >> 16);
    hdr[2] = (uint8_t)(len >> 8);
    hdr[3] = (uint8_t)len;

    if ((rc = syna_buf_add(out, hdr, 4)) != SYNA_OK) return rc;
    if ((rc = syna_buf_add(out, body, len)) != SYNA_OK) return rc;

    /* transcript */
    if ((rc = syna_buf_add(&t->hs_msgs, hdr, 4)) != SYNA_OK) return rc;
    return syna_buf_add(&t->hs_msgs, body, len);
}

static void hs_hash(syna_tls *t, uint8_t out[32])
{
    SHA256(t->hs_msgs.p, t->hs_msgs.len, out);
}

static int make_client_hello(syna_tls *t, syna_buf *out)
{
    syna_buf h = { 0 };
    static const uint8_t sessid[7] = { 0, 0, 0, 0, 0, 0, 0 };
    int rc = SYNA_ERR_NOMEM;

    if (RAND_bytes(t->client_random, 32) != 1)
        return SYNA_ERR_PROTO;

    if (buf_u8(&h, 0x03) || buf_u8(&h, 0x03)) goto out;          /* TLS 1.2 */
    if (syna_buf_add(&h, t->client_random, 32)) goto out;
    if (buf_u8(&h, sizeof sessid)) goto out;
    if (syna_buf_add(&h, sessid, sizeof sessid)) goto out;

    if (buf_be16(&h, 6)) goto out;                               /* cipher suites */
    if (buf_be16(&h, 0xc005)) goto out;   /* ECDH-ECDSA-AES256-CBC-SHA: the real one */
    if (buf_be16(&h, 0x003d)) goto out;
    if (buf_be16(&h, 0x008d)) goto out;

    if (buf_u8(&h, 0)) goto out;          /* compression list length 0, not 1 */

    /* The extension block length is written two short of the truth. The
     * firmware expects exactly this, so reproduce the bug faithfully. */
    if (buf_be16(&h, 10)) goto out;
    if (buf_be16(&h, 0x0004) || buf_be16(&h, 2) || buf_be16(&h, 0x0017)) goto out;
    if (buf_be16(&h, 0x000b) || buf_be16(&h, 2) ||
        buf_u8(&h, 1) || buf_u8(&h, 0)) goto out;

    rc = neg_add(t, out, 0x01, h.p, h.len);
out:
    syna_buf_free(&h);
    return rc;
}

static int make_certs(syna_tls *t, syna_buf *out)
{
    syna_buf c = { 0 };
    int rc = SYNA_ERR_NOMEM;
    int i;

    /* Two identical length prefixes, both carrying the raw certificate length
     * rather than the length of what follows. Non-conforming, but required. */
    for (i = 0; i < 2; i++) {
        if (buf_u8(&c, 0)) goto out;
        if (buf_be16(&c, (uint16_t)t->cert_len)) goto out;
    }
    if (buf_u8(&c, 0xac) || buf_u8(&c, 0x16)) goto out;
    if (syna_buf_add(&c, t->cert, t->cert_len)) goto out;

    rc = neg_add(t, out, 0x0b, c.p, c.len);
out:
    syna_buf_free(&c);
    return rc;
}

static int make_client_kex(syna_tls *t, syna_buf *out)
{
    uint8_t body[65];
    const EC_GROUP *g = EC_KEY_get0_group(t->session_key);
    const EC_POINT *pub = EC_KEY_get0_public_key(t->session_key);
    size_t n;

    n = EC_POINT_point2oct(g, pub, POINT_CONVERSION_UNCOMPRESSED,
                           body, sizeof body, NULL);
    if (n != sizeof body)
        return SYNA_ERR_PROTO;

    return neg_add(t, out, 0x10, body, n);
}

static int make_cert_verify(syna_tls *t, syna_buf *out)
{
    uint8_t digest[32];
    uint8_t sig[128];
    unsigned int siglen = sizeof sig;

    hs_hash(t, digest);
    if (ECDSA_sign(0, digest, sizeof digest, sig, &siglen, t->priv_key) != 1) {
        syna_dbg("ECDSA signature over the transcript failed");
        return SYNA_ERR_PROTO;
    }
    return neg_add(t, out, 0x0f, sig, siglen);
}

static int make_finished(syna_tls *t, syna_buf *out)
{
    uint8_t digest[32], verify[12];
    syna_buf seed = { 0 };
    uint8_t hdr[4];
    int rc = SYNA_ERR_NOMEM;

    hs_hash(t, digest);
    if (syna_buf_add(&seed, "client finished", 15)) goto out;
    if (syna_buf_add(&seed, digest, 32)) goto out;
    prf(t->master_secret, sizeof t->master_secret, seed.p, seed.len, verify, sizeof verify);

    /* From here on our records are encrypted. */
    t->secure_tx = 1;

    hdr[0] = 0x14;
    hdr[1] = 0;
    hdr[2] = 0;
    hdr[3] = sizeof verify;
    if (syna_buf_add(out, hdr, 4)) goto out;
    rc = syna_buf_add(out, verify, sizeof verify);
out:
    syna_buf_free(&seed);
    return rc;
}

/* Wrap a payload in a TLS record, encrypting it once the session is up. */
static int make_record(syna_tls *t, uint8_t type, const uint8_t *body, size_t len,
                       syna_buf *out)
{
    syna_buf inner = { 0 };
    const uint8_t *payload = body;
    size_t plen = len;
    int rc;

    if (t->secure_tx) {
        syna_buf sealed = { 0 };

        if ((rc = syna_buf_add(&inner, body, len)) != SYNA_OK) goto fail;
        if ((rc = tls_sign(t, type, &inner)) != SYNA_OK) goto fail;
        if ((rc = tls_encrypt(t, inner.p, inner.len, &sealed)) != SYNA_OK) {
            syna_buf_free(&sealed);
            goto fail;
        }
        syna_buf_free(&inner);
        inner = sealed;
        payload = inner.p;
        plen = inner.len;
    }

    if ((rc = buf_u8(out, type)) != SYNA_OK) goto fail;
    if ((rc = buf_u8(out, 3)) != SYNA_OK) goto fail;
    if ((rc = buf_u8(out, 3)) != SYNA_OK) goto fail;
    if ((rc = buf_be16(out, (uint16_t)plen)) != SYNA_OK) goto fail;
    rc = syna_buf_add(out, payload, plen);
fail:
    syna_buf_free(&inner);
    return rc;
}

/* --------------------------------------------------------------------------
 * Handshake response handling
 * ----------------------------------------------------------------------- */
static int handle_server_hello(syna_tls *t, const uint8_t *p, size_t len)
{
    uint16_t suite;
    size_t idlen;

    if (len < 2 + 32 + 1)
        return SYNA_ERR_PROTO;
    if (p[0] != 3 || p[1] != 3) {
        syna_dbg("server offered TLS %u.%u", p[0], p[1]);
        return SYNA_ERR_PROTO;
    }
    memcpy(t->server_random, p + 2, 32);
    idlen = p[34];
    if (len < 35 + idlen + 3)
        return SYNA_ERR_PROTO;

    suite = (uint16_t)((p[35 + idlen] << 8) | p[36 + idlen]);
    if (suite != 0xc005) {
        syna_dbg("server chose unsupported cipher suite %04x", suite);
        return SYNA_ERR_PROTO;
    }
    if (p[37 + idlen] != 0) {
        syna_dbg("server asked for compression");
        return SYNA_ERR_PROTO;
    }
    return SYNA_OK;
}

static int handle_server_finished(syna_tls *t, const uint8_t *p, size_t len)
{
    uint8_t digest[32], verify[12];
    syna_buf seed = { 0 };
    int rc = SYNA_ERR_NOMEM;

    hs_hash(t, digest);
    if (syna_buf_add(&seed, "server finished", 15)) goto out;
    if (syna_buf_add(&seed, digest, 32)) goto out;
    prf(t->master_secret, sizeof t->master_secret, seed.p, seed.len, verify, sizeof verify);

    if (len != sizeof verify || memcmp(verify, p, sizeof verify) != 0) {
        syna_dbg("server Finished verify_data mismatch");
        rc = SYNA_ERR_PROTO;
        goto out;
    }
    syna_dbg("server Finished verified");
    rc = SYNA_OK;
out:
    syna_buf_free(&seed);
    return rc;
}

static int handle_handshake_records(syna_tls *t, uint8_t *p, size_t len)
{
    uint8_t *plain = NULL;
    int rc = SYNA_OK;

    if (t->secure_rx) {
        size_t n = len;
        plain = malloc(len ? len : 1);
        if (!plain)
            return SYNA_ERR_NOMEM;
        if ((rc = tls_decrypt(t, p, len, plain, &n)) != SYNA_OK) goto out;
        if ((rc = tls_validate(t, 0x16, plain, &n)) != SYNA_OK) goto out;
        p = plain;
        len = n;
    }

    while (len >= 4) {
        uint8_t type = p[0];
        size_t l = ((size_t)p[1] << 16) | ((size_t)p[2] << 8) | p[3];
        const uint8_t *body = p + 4;

        if (l > len - 4) {
            rc = SYNA_ERR_PROTO;
            goto out;
        }

        switch (type) {
        case 0x02: rc = handle_server_hello(t, body, l); break;
        case 0x0d: rc = SYNA_OK; break;                     /* certificate request */
        case 0x0e: rc = SYNA_OK; break;                     /* server hello done */
        case 0x14: rc = handle_server_finished(t, body, l); break;
        default:
            syna_dbg("unexpected handshake message 0x%02x", type);
            rc = SYNA_ERR_PROTO;
        }
        if (rc != SYNA_OK)
            goto out;

        if ((rc = syna_buf_add(&t->hs_msgs, p, 4 + l)) != SYNA_OK) goto out;

        p   += 4 + l;
        len -= 4 + l;
    }
out:
    free(plain);
    return rc;
}

/* Walk the records in a reply, returning any application data it carried. */
static int parse_response(syna_tls *t, uint8_t *p, size_t len, syna_buf *app_out)
{
    int rc;

    while (len >= 5) {
        uint8_t type = p[0];
        size_t sz;

        if (p[1] != 3 || p[2] != 3) {
            syna_dbg("record with TLS version %u.%u", p[1], p[2]);
            return SYNA_ERR_PROTO;
        }
        sz = ((size_t)p[3] << 8) | p[4];
        if (sz > len - 5)
            return SYNA_ERR_PROTO;

        switch (type) {
        case 0x16:
            if ((rc = handle_handshake_records(t, p + 5, sz)) != SYNA_OK)
                return rc;
            break;

        case 0x14:
            if (sz != 1 || p[5] != 1)
                return SYNA_ERR_PROTO;
            t->secure_rx = 1;
            break;

        case 0x17: {
            uint8_t *plain;
            size_t n = sz;

            if (!t->secure_rx) {
                syna_dbg("application data before the session was secured");
                return SYNA_ERR_PROTO;
            }
            plain = malloc(sz ? sz : 1);
            if (!plain)
                return SYNA_ERR_NOMEM;
            rc = tls_decrypt(t, p + 5, sz, plain, &n);
            if (rc == SYNA_OK)
                rc = tls_validate(t, 0x17, plain, &n);
            if (rc == SYNA_OK && app_out)
                rc = syna_buf_add(app_out, plain, n);
            free(plain);
            if (rc != SYNA_OK)
                return rc;
            break;
        }

        case 0x15:
            syna_dbg("sensor sent a TLS alert");
            return SYNA_ERR_PROTO;

        default:
            syna_dbg("unknown record type 0x%02x", type);
            return SYNA_ERR_PROTO;
        }

        p   += 5 + sz;
        len -= 5 + sz;
    }
    return SYNA_OK;
}

/* --------------------------------------------------------------------------
 * Key schedule
 * ----------------------------------------------------------------------- */
static int make_keys(syna_tls *t)
{
    uint8_t pre_master[32];
    uint8_t key_block[0x120];
    syna_buf seed = { 0 };
    int rc = SYNA_ERR_NOMEM;

    t->session_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!t->session_key)
        return SYNA_ERR_NOMEM;
    if (EC_KEY_generate_key(t->session_key) != 1)
        return SYNA_ERR_PROTO;

    if (ECDH_compute_key(pre_master, sizeof pre_master,
                         EC_KEY_get0_public_key(t->ecdh_q),
                         t->session_key, NULL) != (int)sizeof pre_master) {
        syna_dbg("ECDH agreement failed");
        return SYNA_ERR_PROTO;
    }

    if (syna_buf_add(&seed, t->client_random, 32)) goto out;
    if (syna_buf_add(&seed, t->server_random, 32)) goto out;

    {
        syna_buf s = { 0 };
        if (syna_buf_add(&s, "master secret", 13)) { syna_buf_free(&s); goto out; }
        if (syna_buf_add(&s, seed.p, seed.len))    { syna_buf_free(&s); goto out; }
        prf(pre_master, sizeof pre_master, s.p, s.len,
            t->master_secret, sizeof t->master_secret);
        syna_buf_free(&s);
    }
    {
        syna_buf s = { 0 };
        if (syna_buf_add(&s, "key expansion", 13)) { syna_buf_free(&s); goto out; }
        if (syna_buf_add(&s, seed.p, seed.len))    { syna_buf_free(&s); goto out; }
        prf(t->master_secret, sizeof t->master_secret, s.p, s.len,
            key_block, sizeof key_block);
        syna_buf_free(&s);
    }

    memcpy(t->sign_key,       key_block + 0x00, 32);
    memcpy(t->validation_key, key_block + 0x20, 32);
    memcpy(t->encryption_key, key_block + 0x40, 32);
    memcpy(t->decryption_key, key_block + 0x60, 32);

    OPENSSL_cleanse(pre_master, sizeof pre_master);
    OPENSSL_cleanse(key_block, sizeof key_block);
    rc = SYNA_OK;
out:
    syna_buf_free(&seed);
    return rc;
}

/* --------------------------------------------------------------------------
 * Session establishment
 * ----------------------------------------------------------------------- */
void syna_tls_reset(syna_tls *t)
{
    t->secure_tx = t->secure_rx = 0;
    t->hs_msgs.len = 0;
}

void syna_tls_free(syna_tls *t)
{
    syna_buf_free(&t->hs_msgs);
    free(t->cert);
    t->cert = NULL;
    if (t->priv_key)    { EC_KEY_free(t->priv_key);    t->priv_key = NULL; }
    if (t->ecdh_q)      { EC_KEY_free(t->ecdh_q);      t->ecdh_q = NULL; }
    if (t->session_key) { EC_KEY_free(t->session_key); t->session_key = NULL; }
    OPENSSL_cleanse(t->sign_key, 32);
    OPENSSL_cleanse(t->validation_key, 32);
    OPENSSL_cleanse(t->encryption_key, 32);
    OPENSSL_cleanse(t->decryption_key, 32);
    OPENSSL_cleanse(t->master_secret, sizeof t->master_secret);
}

int syna_tls_open(syna_dev *d)
{
    syna_tls *t = &d->tls;
    syna_buf out = { 0 }, hs = { 0 }, reply = { 0 };
    int rc;

    syna_tls_reset(t);

    /* --- flight 1: ClientHello ------------------------------------------ */
    if ((rc = make_client_hello(t, &hs)) != SYNA_OK) goto out;
    if ((rc = make_record(t, 0x16, hs.p, hs.len, &out)) != SYNA_OK) goto out;

    rc = syna_vcsfw_tls_xfer(d, out.p, out.len, &reply);
    if (rc != SYNA_OK) goto out;
    if ((rc = parse_response(t, reply.p, reply.len, NULL)) != SYNA_OK) goto out;

    /* --- derive the session keys ---------------------------------------- */
    if ((rc = make_keys(t)) != SYNA_OK) goto out;

    /* --- flight 2: Certificate, ClientKeyExchange, CertificateVerify,
     *               ChangeCipherSpec, Finished -------------------------- */
    hs.len = 0;
    out.len = 0;
    reply.len = 0;

    if ((rc = make_certs(t, &hs)) != SYNA_OK) goto out;
    if ((rc = make_client_kex(t, &hs)) != SYNA_OK) goto out;
    if ((rc = make_cert_verify(t, &hs)) != SYNA_OK) goto out;
    if ((rc = make_record(t, 0x16, hs.p, hs.len, &out)) != SYNA_OK) goto out;

    {
        static const uint8_t ccs[] = { 0x14, 0x03, 0x03, 0x00, 0x01, 0x01 };
        if ((rc = syna_buf_add(&out, ccs, sizeof ccs)) != SYNA_OK) goto out;
    }

    hs.len = 0;
    if ((rc = make_finished(t, &hs)) != SYNA_OK) goto out;
    if ((rc = make_record(t, 0x16, hs.p, hs.len, &out)) != SYNA_OK) goto out;

    rc = syna_vcsfw_tls_xfer(d, out.p, out.len, &reply);
    if (rc != SYNA_OK) goto out;
    if ((rc = parse_response(t, reply.p, reply.len, NULL)) != SYNA_OK) goto out;

    if (!t->secure_tx || !t->secure_rx) {
        syna_dbg("handshake finished without a secure session");
        rc = SYNA_ERR_PROTO;
        goto out;
    }

    syna_dbg("TLS session established");
    rc = SYNA_OK;
out:
    syna_buf_free(&out);
    syna_buf_free(&hs);
    syna_buf_free(&reply);
    if (rc != SYNA_OK)
        syna_tls_reset(t);
    return rc;
}

/* Send one VCSFW command inside the session and return its reply. */
int syna_tls_cmd(syna_dev *d, const uint8_t *cmd, size_t len, syna_buf *out)
{
    syna_tls *t = &d->tls;
    syna_buf rec = { 0 }, reply = { 0 };
    int rc;

    if (!t->secure_tx || !t->secure_rx)
        return SYNA_ERR_PROTO;

    if ((rc = make_record(t, 0x17, cmd, len, &rec)) != SYNA_OK) goto out;

    /* Application records travel on their own, without the 0x44 wrapper. */
    rc = syna_vcsfw_raw(d, rec.p, rec.len, &reply);
    if (rc != SYNA_OK) goto out;

    rc = parse_response(t, reply.p, reply.len, out);
out:
    syna_buf_free(&rec);
    syna_buf_free(&reply);
    return rc;
}
