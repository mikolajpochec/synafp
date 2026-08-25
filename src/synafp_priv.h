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

/* Per-sensor-type geometry and its capture program (see src/synafp_tables.c). */
typedef struct {
    uint16_t       sensor_type;
    int            bytes_per_line;
    int            line_width;
    int            repeat_multiplier;
    int            lines_per_calibration_data;
    int            key_calibration_line;
    int            calibration_frames;
    int            calibration_iterations;
    int            line_update_type;
    const uint8_t *prog;
    size_t         prog_len;
    const uint8_t *calib_blob;
    size_t         calib_blob_len;
} syna_type_info;

/* Identification table: (major, version) as reported by command 0x75. */
typedef struct {
    uint16_t    major;
    uint16_t    type;
    uint8_t     version;
    uint8_t     version_mask;
    const char *name;
} syna_dev_info;

extern const syna_dev_info syna_dev_info_table[];
extern const int syna_dev_info_table_len;
const syna_dev_info *syna_dev_info_lookup(uint16_t major, uint16_t version);

/* Initialisation blobs, per device (see src/synafp_tables.c). */
typedef struct {
    uint16_t       vid, pid;
    const uint8_t *init_hardcoded;
    size_t         init_hardcoded_len;
    const uint8_t *init_clean_slate;
    size_t         init_clean_slate_len;
    const uint8_t *db_write_enable;
    size_t         db_write_enable_len;
} syna_dev_blobs;

extern const syna_dev_blobs syna_blob_table[];
extern const int syna_blob_table_len;
const syna_dev_blobs *syna_blobs_lookup(uint16_t vid, uint16_t pid);
int syna_send_init(syna_dev *d);

extern const syna_type_info syna_type_table[];
extern const int syna_type_table_len;
const syna_type_info *syna_type_lookup(uint16_t sensor_type);

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

    /* capture state, filled in by syna_sensor_setup() */
    const syna_type_info *type_info;
    uint16_t              sensor_type;
    const char           *model_name;
    int                   key_calibration_line;
    int                   lines_per_frame;
    syna_buf              factory_calib;  /* factory calibration values */
    syna_buf              calib_data;     /* per-line calibration, may be empty */
};

int syna_db_value(syna_dev *d, uint16_t dbid, uint16_t *type, syna_buf *out);
int syna_db_lookup_user(syna_dev *d, uint16_t storage, const uint8_t *ident,
                        size_t ident_len, uint16_t *dbid);
int syna_db_new_record(syna_dev *d, uint16_t parent, uint16_t type, uint16_t storage,
                       const uint8_t *data, size_t len, uint16_t *recid);
int syna_identity_for_user(const char *username, syna_buf *out);

/* capture internals */
int syna_build_capture_program(syna_dev *d, syna_capture_mode mode, syna_buf *out);
int syna_interrupt_read(syna_dev *d, uint8_t *buf, int cap, int *len, unsigned timeout_ms);
int syna_wait_interrupt(syna_dev *d, uint8_t *buf, int cap, int *len, unsigned overall_ms);

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
