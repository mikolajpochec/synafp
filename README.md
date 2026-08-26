# synafp

Userspace driver for Synaptics/Validity **VCSFW** fingerprint sensors — the
match-on-chip readers in many ThinkPads. Tested on `06cb:009a` (sensor type
`0x199`); initialisation blobs are present for `138a:0090`, `138a:0097` and
`138a:009d`, untested. `06cb:009a` is not supported by libfprint, whose
synaptics driver is a different protocol family entirely.

Working: sessions, capture, matching, enrolment, verification, deletion,
on-sensor database, PAM, and an fprintd-compatible D-Bus service. Untested:
`synafp calibrate`. Not implemented: pairing a sensor whose credentials have
been wiped.

## Install

```sh
make && sudo make install
```

Needs a C compiler, `make`, `pkg-config`, and headers for `libusb-1.0`,
OpenSSL and PAM. `libsystemd` is optional and enables the D-Bus service.

| Distribution | Packages |
|---|---|
| Debian/Ubuntu | `build-essential pkg-config libusb-1.0-0-dev libssl-dev libpam0g-dev libsystemd-dev` |
| Fedora/RHEL | `gcc make pkgconf-pkg-config libusb1-devel openssl-devel pam-devel systemd-devel` |
| Arch | `base-devel libusb openssl pam systemd-libs` |
| Alpine | `build-base pkgconf libusb-dev openssl-dev linux-pam-dev` |

`PREFIX`, `LIBDIR`, `PAMDIR`, `UDEVDIR`, `LIBEXECDIR`, `UNITDIR`, `STATEDIR`
and `DESTDIR` are honoured for packaging.

The sensor needs a per-line calibration table before it will detect a finger —
without it, scans complete instantly and report no match. Generate one with
`sudo synafp calibrate` (this **erases flash partition 6**), or import an
existing table with `sudo synafp calib-import <file>`. It lives in
`/var/lib/synafp/calib-data.bin` and loads automatically.

Stop any competing daemon first: `sudo systemctl mask fprintd open-fprintd
python3-validity`. Only one process can hold the sensor, and they are usually
enabled by default.

## Use

```sh
sudo synafp info                  # sensor, firmware, flash layout
sudo synafp enroll right-index    # touch repeatedly until it says done
sudo synafp verify                # check a finger is yours
sudo synafp db                    # what is stored on the sensor
sudo synafp delete right-index    # or: delete all
```

Fingers are `left-`/`right-` plus `thumb`, `index`, `middle`, `ring`,
`little`. Exit status: `0` success, `2` clean non-match, `1` error. Add `-v`
for protocol tracing, `-r` to reset a wedged sensor.

Most commands need root: the session key derives from the DMI product serial,
which only root can read. The CLI drops privileges immediately afterwards.

For login and lock screens, `sudo ./dist/enable-pam.sh` adds the module above
your password check (`--undo` reverses it), and
`sudo systemctl enable --now synafp-fprintd` provides the fprintd D-Bus
interface that screen lockers use to arm the reader before you type. Test
without touching a real login path first:

```sh
make pamtest synafp-test
sudo install -m 0644 synafp-test /etc/pam.d/synafp-test && sudo ./pamtest
```

## Security

- **A fingerprint is a convenience factor, not a secret.** You leave copies of
  it everywhere and cannot change it. Reasonable for unlocking a session you
  are sitting at; weak for anything granting new authority. Keep it off `sudo`,
  `su` and `sshd` — see `dist/synafp-pam-example`.
- **Matching happens on the sensor.** The host never sees an image and
  templates never leave the chip.
- **The host binding is weak by design.** The key protecting the private key
  derives from DMI values plus constants from the vendor driver, none of them
  secret. It binds a sensor to a *chassis*, not a *user*.
- **Anyone with root can enrol a finger** onto any account, and it survives a
  password change. Enrolment and deletion are logged to `LOG_AUTH`.
- **Not audited.** Reverse-engineered against an undocumented protocol.

Mitigations in the code: root is needed only for the DMI read and USB claim,
after which privileges are dropped; the build is hardened (PIE, RELRO, stack
protector, `_FORTIFY_SOURCE`); derived keys are wiped on close and the DMI
serial is never logged; `tools/fuzzparse.c` runs the device-facing parsers
under ASan and UBSan. The PAM module is the exception — it must stay root.

## Contributing

**Before you start.** Most of this driver cannot be exercised without the
hardware, and the parts that can be are the parts least likely to be wrong.
If you have a sensor, say which one (`sudo synafp info`) in your PR. If you
do not, the parsers, table generation and D-Bus surface are still testable
and still get bugs.

**What a change has to clear.**

```sh
make clean && make                                  # no warnings; -Wall -Wextra is on
make fuzzparse CFLAGS="-O1 -g -fsanitize=address,undefined" && ./fuzzparse
```

The fuzzer must finish clean. The sensor is a peripheral, not a trusted input:
it can be faulty, firmware-crashed, or swapped for something hostile, so every
parser reachable from its replies has to survive arbitrary bytes. A past bug
here recursed on whatever record tree the sensor reported and would have blown
the stack on a cycle.

If you touch `synafp_capture.c`, diff the generated program against a
known-good implementation before and after — it is the one part with an
external oracle, and byte-identical output is the bar:

```sh
sudo synafp progdump > after.txt
```

`src/synafp_tables.c` is **generated — never edit it by hand.** Change
`tools/gen_tables.py` and regenerate. Two vendor blobs were once transcribed
manually and both were wrong, which is why nothing is typed in any more.

**Conventions.** C99, four spaces, no tabs. Comments explain *why*, not what —
particularly where the protocol is strange, because most of it is and the next
reader will assume a mistake otherwise. Every entry point validates its inputs
and returns a negative `SYNA_ERR_*`; nothing calls `exit()` outside `main`.
Anything privileged does the minimum while privileged and drops as early as it
can.

**Adding a sensor.** Identification is table-driven; `synafp sensor` reports
the model and type of an unrecognised device. Capture also needs per-type
geometry, a capture program and initialisation blobs — add them to `SUPPORTED`
and `DEVICES` in `tools/gen_tables.py` and regenerate (needs python-validity
importable; the output is committed so building synafp never requires it).
Only the type 1 line-update variant exists so far. The table records which
variant a sensor needs, so an unsupported one fails cleanly instead of wedging
the firmware.

**Reporting a bug.** Include `sudo synafp -vv <command>` and, for anything
involving a lock or login screen, `journalctl -u synafp-fprintd -n 30`.
Almost every failure in practice has been environmental rather than a protocol
bug: another daemon holding the sensor, missing calibration, or a sandbox
denying something the driver needs. The error messages name those cases
directly — trust them before reaching for a hex dump. Instant, repeated
`no-match` results almost always mean the calibration table is missing or
unreadable, not that matching is broken.

**Testing auth changes safely.** `tools/pamtest.c` runs the PAM module against
a throwaway service so a broken module cannot lock anyone out. Never test on a
real login path first, and keep a root shell open in another terminal when you
do get there:

```sh
make pamtest synafp-test
sudo install -m 0644 synafp-test /etc/pam.d/synafp-test && sudo ./pamtest
```

```
src/synafp_core.c     USB transport, discovery, session lifecycle
src/synafp_vcsfw.c    command layer, flash, initialisation
src/synafp_tls.c      the bespoke TLS channel
src/synafp_capture.c  capture program, scanning, matching, calibration
src/synafp_db.c       on-sensor template database
src/synafp_enroll.c   enrolment and verification
src/synafp_auth.c     setuid helper for unprivileged callers
src/synafp_fprintd.c  fprintd-compatible D-Bus service
src/synafp_tables.c   GENERATED - see tools/gen_tables.py
```

LGPL-2.1-or-later. The capture programs, geometry tables and initialisation
blobs originate in Synaptics' Windows driver and are reproduced as
[python-validity](https://github.com/uunicorn/python-validity) distributes
them. This driver is an independent implementation - python-validity served as
protocol documentation and as a correctness oracle, and the generated capture
programs are verified byte-identical against it.
