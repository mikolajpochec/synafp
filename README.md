# synafp

A userspace driver for Synaptics/Validity **VCSFW** fingerprint sensors — the
match-on-chip readers fitted to many ThinkPads and other business laptops.

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

Working and tested on hardware: sessions, capture, matching, enrolment,
verification, deletion, and the on-sensor database.

Not verified: the PAM module builds but has had little real use, and
`synafp calibrate` has never been run against a sensor.

Not implemented: pairing a sensor whose credentials have been wiped.

### Calibration

The sensor needs two calibration artefacts before it will read a finger: a
reference image, kept in its own flash, and a per-line correction table, which
is host state. Without the latter the sensor arms but never detects a finger.

```sh
sudo synafp calibrate      # captures blank frames; keep clear of the sensor
```

This **erases and rewrites flash partition 6**, so it asks for confirmation
(`-y` skips it). The correction table is written to
`/var/lib/synafp/calib-data.bin` and loaded automatically thereafter.

If python-validity has already calibrated this machine, its table can be
imported instead of regenerating one:

```sh
sudo synafp calib-import /var/run/python-validity/calib-data.bin
```

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
sudo synafp delete right-index    # remove one enrolment
sudo synafp delete all            # remove all of this user's enrolments
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

Screen lockers (`hyprlock`, `swaylock`, and friends) authenticate as the
locked-out user rather than as root, so the module cannot reach the DMI serial
itself. It hands off to `synafp-auth`, a small setuid helper — the same shape
of solution `pam_unix` uses with `unix_chkpwd`. `make install` puts it in
place; without it, lockers fall through to the password every time.

To wire it into login, the display manager and the screen locker in one go:

```sh
sudo ./dist/enable-pam.sh          # edits the right stack, keeps a backup
sudo ./dist/enable-pam.sh --undo   # puts it back
```

On Arch that is `system-login`, which covers `login`, `sddm`, `hyprlock` and
anything else including `login` — and deliberately *not* `sudo` or `su`, which
go straight to `system-auth`.

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

- **A fingerprint is a convenience factor, not a secret.** You leave copies of
  it everywhere and cannot change it. Good for unlocking a session you are
  already sitting at; weak for anything granting new authority. See
  `dist/synafp-pam-example` for where not to put it.
- **Matching happens on the sensor.** The host never sees an image, and
  templates never leave the chip.
- **The host binding is weak by design.** The key protecting the private key
  derives from the laptop's DMI values plus constants from the vendor driver.
  None of that is secret: it binds a sensor to a *chassis*, not to a *user*.
- **Anyone with root can enrol a finger** onto any account, and that survives a
  password change. Enrolment and deletion are logged to `LOG_AUTH`; `synafp db`
  shows what is stored.
- **Not audited.** Reverse-engineered, against an undocumented protocol.

What the code does about it: root is needed only for the DMI read and the USB
claim, both inside `syna_open()`, and the CLI drops privileges immediately
after — so every parser fed by the sensor runs unprivileged. The build is
hardened (PIE, RELRO, stack protector, `_FORTIFY_SOURCE`), derived keys are
wiped on close, the DMI serial is never logged, and `tools/fuzzparse.c` runs
the device-facing parsers under ASan and UBSan.

The PAM module is the exception: it has to stay root, so that path keeps the
full exposure.

## How it works

Commands go out on bulk endpoint `0x01` and replies come back on `0x81`,
prefixed with a little-endian status word. Almost everything interesting
requires a TLS 1.2 session, tunnelled through command `0x44` during the
handshake and then carried as bare TLS records.

The session is TLS in shape but not in detail — cipher suite `0xC005`, and
several length fields that are wrong with respect to RFC 5246 and must be
reproduced wrongly to interoperate. A stock TLS library cannot be pointed at
it, which is why the handshake is implemented by hand.

The client credentials are not on the host. They live in the sensor's flash
(partition 1, readable without a session) with the private key encrypted under
a key derived from this machine's DMI identity — that is what binds a paired
sensor to one laptop.

A scan is driven by a *program*: type/length/value chunks the firmware
executes. A stock program per sensor type is patched before every scan, with
the timeslot table rewritten for the sensor geometry and calibration spliced
in.

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

**`sensor is claimed by another process`** — another fingerprint daemon has it.
These are usually enabled by default and get restarted whenever udev
re-triggers the device, so disable rather than just stop them:

```sh
sudo systemctl disable --now python3-validity open-fprintd fprintd
```

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
