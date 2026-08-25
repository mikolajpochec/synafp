/* synafp - a self-contained userspace driver for Synaptics "Metallica"/Prometheus
 * match-on-chip fingerprint sensors (USB 06cb:00xx, vendor-specific class).
 *
 * Depends only on libusb-1.0 and libc. No glib, no libfprint, no D-Bus, no
 * kernel module. Builds and runs on any Linux/BSD system with libusb.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#ifndef SYNAFP_H
#define SYNAFP_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------------
 * Wire protocol
 *
 * Two nested layers travel over the two bulk endpoints:
 *
 *   FW layer (EP 0x01 OUT / 0x81 IN)
 *     request : [fw_cmd]                       ... optional trailing bytes
 *     reply   : [status_lo][status_hi] ...     status is little-endian u16
 *
 *   BMKT layer, carried inside FW command SYNA_FW_ACE_COMMAND
 *     [0xFE][seq][msg_id][payload_len][payload...]
 *
 * Long-running operations (enroll, verify) emit several BMKT responses. The
 * device signals "another message is waiting" on interrupt EP 0x83; the host
 * then issues SYNA_FW_ASYNCMSG_READ and reads the next reply from EP 0x81.
 * ------------------------------------------------------------------------- */

#define SYNA_VENDOR_ID              0x06cb

#define SYNA_EP_REQUEST             0x01
#define SYNA_EP_REPLY               0x81
#define SYNA_EP_FINGERPRINT         0x82
#define SYNA_EP_INTERRUPT           0x83

/* 263 payload + 1 SPI header + 2 VCSFW header */
#define SYNA_MAX_TRANSFER           266
#define SYNA_INTERRUPT_SIZE         7
#define SYNA_ASYNC_MESSAGE_PENDING  0x04

#define SYNA_FW_GET_VERSION         0x01
#define SYNA_FW_ACE_COMMAND         0xA7
#define SYNA_FW_ASYNCMSG_READ       0xA8
#define SYNA_FW_REPLY_HEADER_LEN    2

#define BMKT_HEADER_ID              0xFE
#define BMKT_HEADER_LEN             4
#define BMKT_MAX_USER_ID_LEN        100
#define BMKT_MAX_PAYLOAD            250
#define BMKT_MAX_TEMPLATES          15
#define BMKT_PART_NUM_LEN           10
#define BMKT_SUPPLIER_ID_LEN        2

/* Commands */
#define BMKT_CMD_FPS_INIT           0x11
#define BMKT_CMD_GET_FPS_MODE       0x21
#define BMKT_CMD_SET_SECURITY_LEVEL 0x31
#define BMKT_CMD_GET_SECURITY_LEVEL 0x34
#define BMKT_CMD_CANCEL_OP          0x41
#define BMKT_CMD_ENROLL_USER        0x51
#define BMKT_CMD_ENROLL_PAUSE       0x52
#define BMKT_CMD_ENROLL_RESUME      0x53
#define BMKT_CMD_ID_USER            0x61
#define BMKT_CMD_VERIFY_USER        0x65
#define BMKT_CMD_GET_TEMPLATE_RECORDS 0x71
#define BMKT_CMD_GET_NEXT_QUERY_RESPONSE 0x72
#define BMKT_CMD_GET_ENROLLED_FINGERS 0x73
#define BMKT_CMD_GET_DATABASE_CAPACITY 0x74
#define BMKT_CMD_DEL_USER_FP        0x81
#define BMKT_CMD_DEL_FULL_DB        0x84
#define BMKT_CMD_POWER_DOWN_NOTIFY  0xA1
#define BMKT_CMD_GET_VERSION        0xB1
#define BMKT_CMD_SENSOR_STATUS      0xD1
#define BMKT_CMD_ID_USER_IN_ORDER   0xE1
#define BMKT_CMD_ID_NEXT_USER       0xE3

/* Responses */
#define BMKT_RSP_FPS_INIT_FAIL      0x12
#define BMKT_RSP_FPS_INIT_OK        0x13
#define BMKT_RSP_FPS_MODE_FAIL      0x22
#define BMKT_RSP_FPS_MODE_REPORT    0x23
#define BMKT_RSP_SET_SECURITY_LEVEL_FAIL   0x32
#define BMKT_RSP_SET_SECURITY_LEVEL_REPORT 0x33
#define BMKT_RSP_GET_SECURITY_LEVEL_FAIL   0x35
#define BMKT_RSP_GET_SECURITY_LEVEL_REPORT 0x36
#define BMKT_RSP_CANCEL_OP_OK       0x42
#define BMKT_RSP_CANCEL_OP_FAIL     0x43
#define BMKT_RSP_ENROLL_READY       0x54
#define BMKT_RSP_ENROLL_REPORT      0x55
#define BMKT_RSP_ENROLL_PAUSED      0x56
#define BMKT_RSP_ENROLL_RESUMED     0x57
#define BMKT_RSP_ENROLL_FAIL        0x58
#define BMKT_RSP_ENROLL_OK          0x59
#define BMKT_RSP_CAPTURE_COMPLETE   0x60
#define BMKT_RSP_ID_READY           0x62
#define BMKT_RSP_ID_FAIL            0x63
#define BMKT_RSP_ID_OK              0x64
#define BMKT_RSP_VERIFY_READY       0x66
#define BMKT_RSP_VERIFY_FAIL        0x67
#define BMKT_RSP_VERIFY_OK          0x68
#define BMKT_RSP_TEMPLATE_RECORDS_REPORT 0x75
#define BMKT_RSP_QUERY_RESPONSE_COMPLETE 0x76
#define BMKT_RSP_GET_ENROLLED_FINGERS_REPORT 0x77
#define BMKT_RSP_DATABASE_CAPACITY_REPORT    0x78
#define BMKT_RSP_QUERY_FAIL         0x79
#define BMKT_RSP_DEL_USER_FP_FAIL   0x82
#define BMKT_RSP_DEL_USER_FP_OK     0x83
#define BMKT_RSP_DEL_FULL_DB_FAIL   0x85
#define BMKT_RSP_DEL_FULL_DB_OK     0x86
#define BMKT_RSP_DELETE_PROGRESS    0x87
#define BMKT_EVT_FINGER_REPORT      0x91
#define BMKT_RSP_POWER_DOWN_READY   0xA2
#define BMKT_RSP_POWER_DOWN_FAIL    0xA3
#define BMKT_RSP_VERSION_INFO       0xB2
#define BMKT_RSP_GET_VERSION_FAIL   0xB3
#define BMKT_RSP_GENERAL_ERROR      0xC1
#define BMKT_RSP_SENSOR_STATUS_REPORT 0xD2
#define BMKT_RSP_SENSOR_STATUS_FAIL   0xD3
#define BMKT_RSP_SEND_NEXT_USER_ID    0xE2

/* Sensor-reported status codes (positive; returned verbatim as -SYNA_ERR_SENSOR
 * base offset, see syna_strerror). */
#define BMKT_STATUS_SUCCESS                 0
#define BMKT_STATUS_NOT_INITIALIZED       101
#define BMKT_STATUS_BUSY                  102
#define BMKT_STATUS_OPERATION_DENIED      103
#define BMKT_STATUS_CORRUPT_MESSAGE       110
#define BMKT_STATUS_INVALID_PARAM         111
#define BMKT_STATUS_UNRECOGNIZED_MESSAGE  112
#define BMKT_STATUS_OP_TIME_OUT           113
#define BMKT_STATUS_GENERAL_ERROR         114
#define BMKT_STATUS_SENSOR_RESET          201
#define BMKT_STATUS_SENSOR_MALFUNCTION    202
#define BMKT_STATUS_SENSOR_TAMPERED       203
#define BMKT_STATUS_SENSOR_NOT_INIT       204
#define BMKT_STATUS_STIMULUS_ERROR        213
#define BMKT_STATUS_CORRUPT_TEMPLATE      300
#define BMKT_STATUS_FEATURE_EXTRACT_FAIL  301
#define BMKT_STATUS_ENROLL_FAIL           302
#define BMKT_STATUS_ENROLLMENT_EXISTS     303
#define BMKT_STATUS_INVALID_FP_IMAGE      304
#define BMKT_STATUS_NO_MATCH              404
#define BMKT_STATUS_DATABASE_FULL         501
#define BMKT_STATUS_DATABASE_EMPTY        502
#define BMKT_STATUS_DATABASE_ACCESS_FAIL  503
#define BMKT_STATUS_NO_RECORD_EXISTS      504
#define BMKT_STATUS_SPOOF_ALERT           801

/* ---------------------------------------------------------------------------
 * Library return codes. All API calls return 0 on success or a negative value.
 * Sensor-reported failures are returned as -(SYNA_ERR_SENSOR_BASE + status).
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
#define SYNA_ERR_SENSOR_BASE   100000   /* -(BASE + status) encodes sensor status */

#define SYNA_IS_SENSOR_ERR(r)  ((r) <= -SYNA_ERR_SENSOR_BASE)
#define SYNA_SENSOR_STATUS(r)  ((int) (-(r) - SYNA_ERR_SENSOR_BASE))

/* Open flags */
#define SYNA_OPEN_RESET     (1u << 0)   /* always USB-reset the device first */
#define SYNA_OPEN_NO_INIT   (1u << 1)   /* skip FPS_INIT */

/* Number of successful touches a full enrolment needs. The sensor drives this
 * itself and reports percentage progress; this is only used for UI hints. */
#define SYNA_ENROLL_SAMPLES 8

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
    char     part[BMKT_PART_NUM_LEN + 1];
    uint8_t  year;
    uint8_t  week;
    uint8_t  patch;
    char     supplier_id[BMKT_SUPPLIER_ID_LEN + 1];
} syna_ace_version;

typedef struct {
    char    user_id[BMKT_MAX_USER_ID_LEN + 1];
    uint8_t finger_id;
    uint8_t template_status;
} syna_template;

typedef struct {
    int     matched;        /* 1 if the finger matched */
    double  score;          /* sensor-reported match confidence */
    uint8_t finger_id;
    char    user_id[BMKT_MAX_USER_ID_LEN + 1];
} syna_match;

typedef struct {
    uint8_t total;
    uint8_t empty;
    uint8_t bad_slots;
    uint8_t corrupt_templates;
    int     has_extended;
} syna_capacity;

/* Events delivered to the caller during long-running operations. */
typedef enum {
    SYNA_EV_READY,           /* sensor armed, waiting for a touch */
    SYNA_EV_FINGER_DOWN,
    SYNA_EV_FINGER_UP,
    SYNA_EV_CAPTURE_OK,      /* one usable image captured */
    SYNA_EV_ENROLL_PROGRESS, /* arg = percent complete */
    SYNA_EV_DELETE_PROGRESS, /* arg = percent complete */
    SYNA_EV_RETRY            /* arg = sensor status explaining the bad touch */
} syna_event;

/* Return non-zero from the callback to request cancellation of the operation. */
typedef int (*syna_cb)(syna_event ev, int arg, void *user);

/* --- lifecycle ----------------------------------------------------------- */
int   syna_open(syna_dev **out, const char *serial, unsigned flags);
void  syna_close(syna_dev *d);
const char *syna_strerror(int rc);
void  syna_set_debug(int level);
const char *syna_serial(const syna_dev *d);
uint16_t syna_product_id(const syna_dev *d);

/* --- informational ------------------------------------------------------- */
int syna_fw_version_get(syna_dev *d, syna_fw_version *out);
int syna_ace_version_get(syna_dev *d, syna_ace_version *out);
int syna_capacity_get(syna_dev *d, syna_capacity *out);
int syna_sensor_status(syna_dev *d, uint8_t *buf, size_t cap, size_t *len);

/* --- biometrics ---------------------------------------------------------- */
int syna_enroll(syna_dev *d, const char *user_id, uint8_t finger,
                syna_cb cb, void *user);
int syna_verify(syna_dev *d, const char *user_id, syna_match *out,
                syna_cb cb, void *user);
int syna_identify(syna_dev *d, const char *const *user_ids, int n_ids,
                  syna_match *out, syna_cb cb, void *user);

/* --- template storage (on-sensor) ---------------------------------------- */
int syna_list(syna_dev *d, syna_template *out, int max, int *count);
int syna_delete(syna_dev *d, const char *user_id, uint8_t finger);
int syna_clear(syna_dev *d, syna_cb cb, void *user);

/* --- misc ---------------------------------------------------------------- */
int syna_cancel(syna_dev *d);        /* safe to call from a signal handler */
int syna_set_timeout(syna_dev *d, unsigned ms);  /* how long to wait for a finger; 0 = forever */
int syna_power_down(syna_dev *d);
const char *syna_finger_name(uint8_t finger_id);
int syna_finger_from_name(const char *name);

#ifdef __cplusplus
}
#endif
#endif /* SYNAFP_H */
