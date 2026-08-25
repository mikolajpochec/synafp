/* synafp - a self-contained userspace driver for Synaptics/Validity VCSFW
 * fingerprint sensors (USB 06cb:009a and the 138a:009x family).
 *
 * Depends only on libusb-1.0, OpenSSL and libc. No libfprint, no fprintd, no
 * D-Bus, no kernel module.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#ifndef SYNAFP_H
#define SYNAFP_H

#include <stdint.h>
#include <stdio.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------------
 * Wire protocol
 *
 *   VCSFW command   EP 0x01 OUT : [cmd][args...]
 *   VCSFW reply     EP 0x81 IN  : [status:u16le][data...]
 *
 * Only a handful of commands work outside a session. Everything that touches
 * fingerprints requires the TLS channel, which is tunnelled through command
 * 0x44 during the handshake and then carried as bare TLS records.
 *
 * The client credentials live in the sensor's own flash, in partition 1,
 * with the private key encrypted under a key derived from this machine's DMI
 * product name and serial. Pairing therefore binds a sensor to one laptop.
 * ------------------------------------------------------------------------- */

#define SYNA_VENDOR_SYNAPTICS   0x06cb
#define SYNA_VENDOR_VALIDITY    0x138a

#define SYNA_EP_REQUEST         0x01
#define SYNA_EP_REPLY           0x81
#define SYNA_EP_DATA            0x82
#define SYNA_EP_INTERRUPT       0x83

/* VCSFW commands used by this driver. */
#define VCSFW_CMD_GET_VERSION   0x01
#define VCSFW_CMD_RESET         0x05
#define VCSFW_CMD_PEEK          0x07
#define VCSFW_CMD_GET_STATUS    0x19
#define VCSFW_CMD_CLEANUPS      0x1a
#define VCSFW_CMD_EVENT_CONFIG  0x57
#define VCSFW_CMD_GET_EVENTS    0x58
#define VCSFW_CMD_FLASH_INFO    0x3e
#define VCSFW_CMD_FLASH_ERASE   0x3f
#define VCSFW_CMD_FLASH_READ    0x40
#define VCSFW_CMD_FLASH_WRITE   0x41
#define VCSFW_CMD_FW_INFO       0x43
#define VCSFW_CMD_TLS_DATA      0x44
#define VCSFW_CMD_IDENTIFY      0x75
#define VCSFW_CMD_FACTORY_BITS  0x6f

#define SYNA_TLS_PARTITION      1
#define SYNA_TLS_FLASH_SIZE     0x1000

#define SYNA_MAX_USER_ID_LEN    100
#define SYNA_MAX_TEMPLATES      16

/* ---------------------------------------------------------------------------
 * Return codes. Every call returns 0 or a negative value. Sensor-reported
 * statuses come back as -(SYNA_ERR_SENSOR_BASE + status).
 * ------------------------------------------------------------------------- */
#define SYNA_OK                 0
#define SYNA_ERR_USB           -1
#define SYNA_ERR_NO_DEVICE     -2
#define SYNA_ERR_PROTO         -3
#define SYNA_ERR_TIMEOUT       -4
#define SYNA_ERR_CANCELLED     -5
#define SYNA_ERR_NOMEM         -6
#define SYNA_ERR_INVAL         -7
#define SYNA_ERR_ACCESS        -8
#define SYNA_ERR_BUSY          -9
#define SYNA_ERR_UNSUPPORTED  -10
#define SYNA_ERR_PAIRING      -11   /* sensor is paired to a different machine */
#define SYNA_ERR_SENSOR_BASE   100000

#define SYNA_IS_SENSOR_ERR(r)  ((r) <= -SYNA_ERR_SENSOR_BASE)
#define SYNA_SENSOR_STATUS(r)  ((int) (-(r) - SYNA_ERR_SENSOR_BASE))

/* Open flags */
#define SYNA_OPEN_RESET     (1u << 0)   /* USB-reset the device first */
#define SYNA_OPEN_NO_TLS    (1u << 1)   /* skip the TLS handshake */

typedef struct syna_dev syna_dev;

typedef struct {
    uint32_t build_time;
    uint32_t build_num;
    uint8_t  version_major;
    uint8_t  version_minor;
    uint8_t  target;
    uint8_t  product;
    uint8_t  silicon_rev;
    uint8_t  formal_release;
    uint8_t  platform;
    uint8_t  patch;
    uint8_t  serial_number[6];
    uint16_t security;
    uint8_t  iface;
    uint8_t  device_type;
} syna_fw_version;

typedef struct {
    uint8_t  id;
    uint8_t  type;
    uint16_t access_lvl;
    uint32_t offset;
    uint32_t size;
} syna_partition;

typedef struct {
    uint16_t       jedec_id0, jedec_id1;
    uint16_t       blocks;
    uint16_t       blocksize;
    int            n_partitions;
    syna_partition partitions[16];
} syna_flash_info;

/* --- lifecycle ----------------------------------------------------------- */
int   syna_open(syna_dev **out, const char *serial, unsigned flags);
void  syna_close(syna_dev *d);
const char *syna_strerror(int rc);
void  syna_set_debug(int level);
const char *syna_serial(const syna_dev *d);
uint16_t syna_product_id(const syna_dev *d);
int   syna_has_session(const syna_dev *d);

/* --- informational ------------------------------------------------------- */
int syna_fw_version_get(syna_dev *d, syna_fw_version *out);
int syna_flash_info_get(syna_dev *d, syna_flash_info *out);
int syna_creds_report(syna_dev *d, FILE *out);

typedef enum {
    SYNA_CALIB_ABSENT = 0,   /* partition is blank: never calibrated here */
    SYNA_CALIB_VALID,        /* reference image present and intact */
    SYNA_CALIB_BAD_HASH,     /* present but corrupt */
    SYNA_CALIB_MALFORMED
} syna_calib_state_t;

typedef struct {
    syna_calib_state_t state;
    uint16_t           magic;
    uint16_t           length;
} syna_calib_info;

typedef enum {
    SYNA_CAPTURE_CALIBRATE = 1,
    SYNA_CAPTURE_IDENTIFY  = 2,
    SYNA_CAPTURE_ENROLL    = 3
} syna_capture_mode;

/* Where on the sensor the finger landed, and how wide the ridges were. */
typedef struct {
    uint16_t x, y, w1, w2;
} syna_capture_result;

/* Result of matching a captured image against the on-sensor database. */
typedef struct {
    int      matched;
    uint32_t user_id;   /* database id, resolve via the template database */
    uint16_t subtype;   /* which finger */
    uint8_t  hash[32];
    int      have_hash;
} syna_match_result;

int syna_match(syna_dev *d, syna_match_result *out);
int syna_sensor_setup(syna_dev *d);
int syna_dump_capture_program(syna_dev *d, syna_capture_mode mode, FILE *out);
int syna_capture(syna_dev *d, syna_capture_mode mode, syna_capture_result *out);
int syna_glow_start(syna_dev *d);
int syna_glow_end(syna_dev *d);
int syna_cancel(syna_dev *d);

int syna_identify_sensor(syna_dev *d, uint16_t *major, uint16_t *minor);
int syna_calib_state(syna_dev *d, syna_calib_info *out);

#ifdef __cplusplus
}
#endif
#endif /* SYNAFP_H */
