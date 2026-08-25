/* synafp_priv.h - internals shared between the library translation units.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#ifndef SYNAFP_PRIV_H
#define SYNAFP_PRIV_H

#define OPENSSL_SUPPRESS_DEPRECATED
#include "synafp.h"

#include <libusb-1.0/libusb.h>
#include <openssl/ec.h>
#include <signal.h>
#include <stdarg.h>

#define SYNA_CMD_TIMEOUT_MS     3000
#define SYNA_REPLY_TIMEOUT_MS   5000
#define SYNA_RX_BUFFER          (128 * 1024)

/* Growable byte buffer. */
typedef struct {
    uint8_t *p;
    size_t   len, cap;
} syna_buf;

int  syna_buf_add(syna_buf *b, const void *data, size_t n);
void syna_buf_free(syna_buf *b);

/* State for the sensor's bespoke TLS 1.2 channel. */
typedef struct {
    uint8_t  psk_encryption_key[32];
    uint8_t  psk_validation_key[32];

    uint8_t *cert;
    size_t   cert_len;
    EC_KEY  *priv_key;      /* our client key, recovered from flash */
    EC_KEY  *ecdh_q;        /* the sensor's static ECDH key */
    EC_KEY  *session_key;   /* our ephemeral key */

    uint8_t  client_random[32];
    uint8_t  server_random[32];
    uint8_t  master_secret[48];
    uint8_t  sign_key[32];
    uint8_t  validation_key[32];
    uint8_t  encryption_key[32];
    uint8_t  decryption_key[32];

    int      have_hwkey;    /* DMI-derived keys available (needs root) */
    syna_buf hs_msgs;       /* handshake transcript */
    int      secure_tx, secure_rx;
} syna_tls;

struct syna_dev {
    libusb_context       *ctx;
    libusb_device_handle *h;
    int                   ifnum;
    uint16_t              vid, pid;
    char                  serial[64];

    volatile sig_atomic_t cancel_req;
    unsigned              op_timeout_ms;

    uint8_t              *rx;        /* scratch for bulk reads */
    syna_fw_version       fw;
    syna_tls              tls;
};

/* core */
extern int syna_debug_level;
void syna_dbg(const char *fmt, ...);
void syna_hexdump(const char *tag, const uint8_t *b, int n);
int  syna_bulk_out(syna_dev *d, const uint8_t *buf, int len, unsigned timeout_ms);
int  syna_bulk_in(syna_dev *d, uint8_t *buf, int cap, int *out_len, unsigned timeout_ms);
int  syna_usb_error(int e);

/* vcsfw */
int syna_vcsfw_raw(syna_dev *d, const uint8_t *out, size_t outlen, syna_buf *reply);
int syna_vcsfw_tls_xfer(syna_dev *d, const uint8_t *records, size_t len, syna_buf *reply);
int syna_vcsfw_cmd(syna_dev *d, const uint8_t *cmd, size_t len, syna_buf *reply);
int syna_vcsfw_call(syna_dev *d, const uint8_t *cmd, size_t len, syna_buf *reply);
int syna_read_flash(syna_dev *d, uint8_t partition, uint32_t addr, uint32_t size,
                    syna_buf *out);
int syna_read_flash_all(syna_dev *d, uint8_t partition, uint32_t start, uint32_t size,
                        syna_buf *out);

/* tls */
int  syna_tls_set_hwkey(syna_tls *t, const char *product_name, const char *serial);
int  syna_tls_set_hwkey_from_dmi(syna_tls *t);
int  syna_tls_parse_flash(syna_tls *t, const uint8_t *p, size_t len);
int  syna_tls_open(syna_dev *d);
int  syna_tls_cmd(syna_dev *d, const uint8_t *cmd, size_t len, syna_buf *out);
void syna_tls_reset(syna_tls *t);
void syna_tls_free(syna_tls *t);

#endif /* SYNAFP_PRIV_H */
