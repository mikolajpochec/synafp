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

Patches welcome — especially from anyone with a sensor this has never been
tested on. Say which one (`sudo synafp info`) and what happened.

Before opening a PR:

```sh
make clean && make                                  # builds warning-free
make fuzzparse CFLAGS="-O1 -g -fsanitize=address,undefined" && ./fuzzparse
```

The fuzzer has to finish clean: the sensor is untrusted input, so anything
parsing its replies must survive arbitrary bytes.

`src/synafp_tables.c` is generated — edit `tools/gen_tables.py` instead.
Testing auth changes? Use `tools/pamtest.c` against a throwaway PAM service
rather than a real login path.

Filing a bug: include `sudo synafp -vv <command>`, plus
`journalctl -u synafp-fprintd -n 30` for lock or login issues. Most problems
turn out to be another daemon holding the sensor, missing calibration, or a
sandbox in the way — the error messages usually name the cause.

LGPL-2.1-or-later. Capture programs and initialisation blobs originate in
Synaptics' Windows driver and are reproduced as
[python-validity](https://github.com/uunicorn/python-validity) distributes
them; that project also served as protocol documentation and as a correctness
oracle for this independent implementation.
