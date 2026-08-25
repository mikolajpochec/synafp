/* fuzzparse.c - hammer the parsers that consume device-supplied data.
 *
 * The sensor is not a trusted input: it is a peripheral that can be faulty,
 * firmware-crashed, or replaced. Every parser reachable from its replies has
 * to survive arbitrary bytes without reading out of bounds. Build with
 * -fsanitize=address,undefined and run.
 *
 *   make fuzzparse && ./fuzzparse [iterations]
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#define _POSIX_C_SOURCE 200809L
#include "synafp_priv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LEN 512

static unsigned long rng_state = 0x2545F4914F6CDD1DUL;

static unsigned rnd(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return (unsigned)(rng_state >> 32);
}

/* Wholly random bytes rarely reach deep code, so also generate inputs that
 * look structurally plausible and only go wrong further in. */
static size_t make_case(uint8_t *buf, int shape)
{
    size_t n = rnd() % MAX_LEN;
    size_t i;

    for (i = 0; i < n; i++)
        buf[i] = (uint8_t)rnd();

    switch (shape) {
    case 1:                                  /* plausible VCSFW reply */
        if (n >= 2) { buf[0] = 0; buf[1] = 0; }
        break;
    case 2:                                  /* plausible TLS record */
        if (n >= 5) {
            buf[0] = (uint8_t)(0x14 + (rnd() % 4));
            buf[1] = 3; buf[2] = 3;
            buf[3] = (uint8_t)(n >> 8); buf[4] = (uint8_t)n;
        }
        break;
    case 3:                                  /* plausible credential block */
        if (n >= 4) {
            buf[0] = (uint8_t)(rnd() % 8); buf[1] = 0;
            buf[2] = (uint8_t)(rnd() % (n > 36 ? n - 36 : 1)); buf[3] = 0;
        }
        break;
    }
    return n;
}

int main(int argc, char **argv)
{
    long iters = (argc > 1) ? atol(argv[1]) : 200000;
    uint8_t buf[MAX_LEN];
    long i;
    long ok = 0, rejected = 0;

    for (i = 0; i < iters; i++) {
        syna_tls t;
        uint16_t vlen = 0;
        size_t n = make_case(buf, (int)(i % 4));

        /* Credential store: block ids, sizes and hashes straight from flash,
         * parsed before any session exists. Every block should be rejected
         * here (the hashes will not match), and rejection must not involve
         * walking off the end of the buffer. */
        memset(&t, 0, sizeof t);
        if (syna_tls_parse_flash(&t, buf, n) == SYNA_OK)
            ok++;
        else
            rejected++;
        syna_tls_free(&t);

        /* Match verdicts: a TLV dictionary supplied by the sensor. */
        syna_dict_get(buf, n, (uint16_t)(rnd() % 6), &vlen);
        syna_dict_get(buf, n, 1, &vlen);
        syna_dict_get(buf, n, 4, &vlen);
    }

    printf("%ld iterations: %ld accepted, %ld rejected, no memory errors\n",
           iters, ok, rejected);
    return 0;
}
