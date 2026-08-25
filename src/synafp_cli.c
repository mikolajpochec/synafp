/* synafp_cli.c - command line front-end.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#define _POSIX_C_SOURCE 200809L
#include "synafp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void usage(FILE *f)
{
    fprintf(f,
"synafp - userspace driver for Synaptics/Validity VCSFW fingerprint sensors\n"
"\n"
"Usage: synafp [options] <command>\n"
"\n"
"Commands:\n"
"  info        sensor identity, firmware and flash layout\n"
"  session     open a secure session and report whether it succeeded\n"
"  creds       inspect the credential store in the sensor's flash\n"
"\n"
"Options:\n"
"  -s <serial>   select a specific sensor\n"
"  -r            USB-reset the sensor first\n"
"  -n            skip the TLS handshake\n"
"  -v            protocol tracing (repeat for hex dumps)\n"
"  -h            this text\n");
}

static const char *access_desc(uint16_t lvl)
{
    switch (lvl) {
    case 2: return "write-only";
    case 7: return "readable without a session";
    default: return "session required";
    }
}

int main(int argc, char **argv)
{
    const char *serial = NULL, *cmd;
    unsigned flags = 0;
    int verbose = 0, i, rc, ret = 0;
    syna_dev *d = NULL;
    syna_fw_version fw;
    syna_flash_info fi;

    for (i = 1; i < argc && argv[i][0] == '-' && argv[i][1]; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(stdout); return 0; }
        else if (!strcmp(a, "-r")) flags |= SYNA_OPEN_RESET;
        else if (!strcmp(a, "-n")) flags |= SYNA_OPEN_NO_TLS;
        else if (!strcmp(a, "-s") && i + 1 < argc) serial = argv[++i];
        else {
            /* allow clustered -v flags such as -vv */
            const char *q = a + 1;
            int ok = *q != '\0';
            while (*q) { if (*q != 'v') { ok = 0; break; } q++; }
            if (ok) { verbose += (int)strlen(a) - 1; continue; }
            fprintf(stderr, "synafp: unknown option %s\n", a);
            usage(stderr);
            return 1;
        }
    }

    if (i >= argc) { usage(stderr); return 1; }
    cmd = argv[i];

    if (verbose)
        syna_set_debug(verbose);

    rc = syna_open(&d, serial, flags);
    if (rc != SYNA_OK) {
        fprintf(stderr, "synafp: %s\n", syna_strerror(rc));
        if (rc == SYNA_ERR_ACCESS)
            fprintf(stderr,
                "synafp: deriving the session key needs the DMI product serial,\n"
                "        which is readable only by root. Try: sudo synafp %s\n", cmd);
        else if (rc == SYNA_ERR_PAIRING)
            fprintf(stderr,
                "synafp: the credentials in the sensor's flash do not decrypt with\n"
                "        this machine's identity, so it is paired elsewhere.\n");
        return 1;
    }

    if (!strcmp(cmd, "info")) {
        printf("Sensor        : %04x (serial %s)\n", syna_product_id(d), syna_serial(d));

        if (syna_fw_version_get(d, &fw) == SYNA_OK) {
            int k;
            printf("Firmware      : %u.%u patch %u (build %u)\n",
                   fw.version_major, fw.version_minor, fw.patch, fw.build_num);
            printf("Silicon       : rev %u, platform %u, product %u, type 0x%02x\n",
                   fw.silicon_rev, fw.platform, fw.product, fw.device_type);
            printf("Security      : 0x%04x\n", fw.security);
            printf("Sensor serial : ");
            for (k = 0; k < 6; k++) printf("%02x", fw.serial_number[k]);
            printf("\n");
        }

        printf("Session       : %s\n",
               syna_has_session(d) ? "established (TLS)" : "not established");

        if (syna_flash_info_get(d, &fi) == SYNA_OK) {
            int k;
            printf("Flash         : JEDEC %04x:%04x, %u blocks of %u bytes\n",
                   fi.jedec_id0, fi.jedec_id1, fi.blocks, fi.blocksize);
            for (k = 0; k < fi.n_partitions; k++)
                printf("  partition %-2u type 0x%02x  %8u bytes at 0x%06x  (%s)\n",
                       fi.partitions[k].id, fi.partitions[k].type,
                       fi.partitions[k].size, fi.partitions[k].offset,
                       access_desc(fi.partitions[k].access_lvl));
        }

    } else if (!strcmp(cmd, "creds")) {
        rc = syna_creds_report(d, stdout);
        if (rc != SYNA_OK) {
            fprintf(stderr, "synafp: %s\n", syna_strerror(rc));
            ret = 1;
        }

    } else if (!strcmp(cmd, "session")) {
        if (syna_has_session(d)) {
            printf("Secure session established with sensor %s.\n", syna_serial(d));
        } else {
            printf("No secure session.\n");
            ret = 1;
        }

    } else {
        fprintf(stderr, "synafp: unknown command '%s'\n", cmd);
        usage(stderr);
        ret = 1;
    }

    syna_close(d);
    return ret;
}
