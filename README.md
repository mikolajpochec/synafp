# synafp

A userspace driver for Synaptics/Validity **VCSFW** fingerprint sensors — the
match-on-chip readers fitted to many ThinkPads and other business laptops.

It depends only on **libusb-1.0, OpenSSL and libc**. No libfprint, no fprintd,
no D-Bus, no polkit, no Python, no kernel module, no systemd unit. It builds
with `make` on any Linux system with those two libraries, and ships a PAM
module that drops into any PAM stack.

## Supported hardware

| USB ID | Sensor | Status |
|--------|--------|--------|
| `06cb:009a` | Synaptics, sensor type `0x199` | developed and tested against this |
| `138a:0090` | Validity | initialisation blobs present, untested |
| `138a:0097` | Validity | initialisation blobs present, untested |
| `138a:009d` | Validity | initialisation blobs present, untested |

Identification is table-driven (422 models), so an unrecognised sensor reports
its model name and exits cleanly rather than misbehaving. Capture additionally
needs per-type data; currently only sensor type `0x199` has it, and only the
type 1 line-update variant is implemented.

`06cb:009a` is worth calling out: it is **not** supported by libfprint, whose
synaptics driver covers a different protocol family entirely and whose ID
table starts at `0x00BD`. The usb.ids description ("Metallica MIS Touch")
misleadingly suggests otherwise.

## Status

| Capability | State |
|---|---|
| USB transport, device discovery | working |
| VCSFW command layer, flash access | working |
| Sensor initialisation | working |
| TLS 1.2 session | working |
| Credential recovery and host binding | working |
| Capture | working |
| Matching / verification | working |
| Enrolment | working |
| Template database enumeration | working |
| PAM module | built, lightly tested |
| Generating calibration data | **not implemented** — see below |
| Deleting a single enrolment | not implemented |
| Pairing an unpaired sensor | not implemented |

### The calibration caveat

The sensor stores a reference image in its own flash, but the *per-line
calibration table* is host-side state. Without it the sensor arms but never
detects a finger. synafp can load and use that table, but **cannot yet
generate it** — that needs the multi-frame averaging pipeline, which is not
implemented.

If you have previously run python-validity, import the table it produced:

```sh
sudo synafp calib-import /var/run/python-validity/calib-data.bin
```

It is installed to `/var/lib/synafp/calib-data.bin` and loaded automatically
thereafter. On a machine that has never been calibrated, synafp cannot
currently bring the sensor up on its own.

## Building

```sh
make
```

Requires a C compiler, `make`, `pkg-config`, and the development files for
`libusb-1.0`, `OpenSSL` (libcrypto) and `PAM`.

| Distribution | Packages |
|---|---|
| Debian/Ubuntu | `build-essential pkg-config libusb-1.0-0-dev libssl-dev libpam0g-dev` |
| Fedora/RHEL | `gcc make pkgconf-pkg-config libusb1-devel openssl-devel pam-devel` |
| Arch | `base-devel libusb openssl pam` |
| openSUSE | `gcc make pkg-config libusb-1_0-devel libopenssl-devel pam-devel` |
| Alpine | `build-base pkgconf libusb-dev openssl-dev linux-pam-dev` |
| Void | `base-devel pkg-config libusb-devel openssl-devel pam-devel` |

## Installing

```sh
sudo make install          # or: ./dist/install.sh
```

`PREFIX`, `BINDIR`, `LIBDIR`, `PAMDIR`, `UDEVDIR`, `DATADIR`, `STATEDIR` and
`DESTDIR` are all honoured, so distribution packaging is straightforward.

## Using it

```sh
sudo synafp info                  # sensor identity, firmware, flash layout
sudo synafp enroll right-index    # record a finger (touch repeatedly)
sudo synafp verify                # check a finger belongs to you
sudo synafp identify              # match against every enrolled record
sudo synafp db                    # what is stored on the sensor
```

Finger names are `left-` / `right-` plus `thumb`, `index`, `middle`, `ring`,
`little`. Exit status is `0` on success, `2` on a clean non-match, `1` on
error.

Useful options: `-u <user>` to act on another account, `-s <serial>` to pick a
sensor, `-r` to USB-reset a wedged one, `-v` / `-vv` for protocol tracing.

### Why it needs root

The TLS session key is derived from this machine's DMI product name and
serial, and `/sys/class/dmi/id/product_serial` is readable only by root. Any
process opening a session must therefore be privileged. This is why the
reference implementation also runs as a root service. PAM modules already run
as root, so login works; the CLI needs `sudo`.

The shipped udev rule still earns its place — it grants the local seat access
to the device node, which is enough for the unprivileged subset (`info`,
`creds`, `sensor`, `-n`).

## PAM integration

See `dist/synafp-pam-example`. In short, above your password module:

```
auth  sufficient  pam_synafp.so  timeout=15 retries=3
```

The module returns `PAM_IGNORE` — not an error — whenever fingerprint
authentication is merely *unavailable*: no sensor, nothing enrolled for this
user, no permission, or the user declined to touch the reader. A `sufficient`
line therefore falls through to the password prompt rather than locking anyone
out. Only a finger that reads successfully but belongs to another record is an
authentication failure.

**Test it safely first.** A throwaway service and a harness are provided, so
you never have to experiment on a real login path:

```sh
make pamtest synafp-test
sudo install -m 0644 synafp-test /etc/pam.d/synafp-test
sudo ./pamtest
```

Only once that behaves as expected should you touch `common-auth` and
friends — and then always with a second terminal open as root.

## Security properties, and their limits

Read this before relying on it for anything that matters.

- **Fingerprints are a convenience factor, not a secret.** You leave them on
  every surface you touch, and you cannot change them. Treat this as "instead
  of retyping a password on a machine you are already sitting at", not as a
  strong second factor.
- **Matching happens on the sensor.** The host never sees a fingerprint image,
  and templates never leave the chip. A compromised host cannot read out
  enrolled fingerprints through this driver.
- **The host binding is weak by design.** The key protecting the client
  private key in flash derives from the laptop's DMI product name and serial,
  plus constants extracted from the vendor driver. Those constants are public
  and the DMI values are not secret — anyone with root on this machine, or
  with physical access and the ability to read the DMI, can derive the same
  key. It binds a sensor to a *chassis*, not to a *user*.
- **`syna_verify` checks identity; `syna_match` does not.** Matching alone
  reports which record a finger belongs to. Authenticating a named user must
  resolve that user's record and insist the match points at it, or any
  enrolled finger would authenticate any account. The PAM module uses
  `syna_verify`.
- **Anyone with root can enrol a finger.** There is no confirmation of user
  presence beyond the touch itself, so root can add their own finger to your
  account. Root can already do anything, but it is worth knowing that a
  fingerprint enrolment survives a password change.
- **No anti-replay on the USB link beyond TLS.** The session protects against
  passive sniffing of the bus. It is not a defence against a malicious device
  substituted in place of the sensor.
- **Not audited.** This is a reverse-engineered driver written against an
  undocumented protocol. It has not had a security review.

If you want fingerprint login on a machine holding anything sensitive, keep
full-disk encryption with a real passphrase at boot, and treat the fingerprint
as unlocking a session, not a vault.

## How it works

Two layers over the sensor's bulk endpoints:

```
VCSFW command   EP 0x01 OUT : [cmd][args...]
VCSFW reply     EP 0x81 IN  : [status:u16le][data...]
```

Almost everything interesting requires a TLS 1.2 session, which is tunnelled
through command `0x44` during the handshake and then carried as bare TLS
records. The session is TLS in shape but not in detail — cipher suite `0xC005`
(ECDH-ECDSA-AES256-CBC-SHA), MAC-then-encrypt with HMAC-SHA256, and several
length fields that are simply wrong with respect to RFC 5246 and must be
reproduced wrongly to interoperate. A stock TLS library cannot be pointed at
it.

The client credentials are not stored on the host. They live in the sensor's
own flash (partition 1, readable without a session), with the private key
encrypted under a key derived from this machine's DMI identity. That is what
binds a paired sensor to one laptop.

A capture is driven by a *program*: a list of type/length/value chunks the
firmware executes. A base program is stored per sensor type, and must be
patched before every scan — the timeslot table is rewritten for the sensor
geometry and calibration values are spliced in.

Source map:

```
src/synafp.h          public API and protocol constants
src/synafp_priv.h     internals shared across the library
src/synafp_core.c     USB transport, discovery, session lifecycle
src/synafp_vcsfw.c    command layer, flash access, initialisation
src/synafp_tls.c      the bespoke TLS channel
src/synafp_capture.c  capture program build, scan, matching, calibration
src/synafp_db.c       on-sensor template database
src/synafp_enroll.c   enrolment and verification
src/synafp_cli.c      the synafp command
src/pam_synafp.c      PAM module
src/synafp_tables.c   GENERATED - see tools/gen_tables.py
tools/gen_tables.py   regenerates the tables (needs python-validity)
tools/pamtest.c       PAM harness that touches no real auth stack
```

## Troubleshooting

**`permission denied`** — most commands need root; see "Why it needs root".

**`no supported fingerprint sensor found`** — check `lsusb | grep -Ei '06cb|138a'`.
If absent, the reader may be disabled in the BIOS (Security → I/O Port Access).

**`sensor is paired to a different computer`** — the credentials in flash do
not decrypt with this machine's DMI identity. The sensor was paired elsewhere;
re-pairing is not implemented.

**Touching the sensor does nothing** — almost always missing calibration data.
See "The calibration caveat".

**Sensor disappears from the bus mid-command** — the firmware crashed and
re-enumerated. It recovers on its own; `synafp -r` forces a reset.

**Conflicts.** `fprintd`, `python-validity` and `open-fprintd` will contend for
the device. Stop them before using synafp.

## Provenance and licence

LGPL-2.1-or-later; see `LICENSE`.

The capture programs, sensor geometry tables and initialisation blobs in
`src/synafp_tables.c` originate in Synaptics' Windows driver. They are
reproduced here the same way [python-validity](https://github.com/uunicorn/python-validity)
distributes them, and `tools/gen_tables.py` extracts them from that project
rather than duplicating the extraction. This driver is an independent
implementation of the protocol; python-validity was used as protocol
documentation and as a correctness oracle — the generated capture programs are
verified byte-identical against it.
