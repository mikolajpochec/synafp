# synafp

A self-contained userspace driver for Synaptics match-on-chip fingerprint
sensors — the `06cb:` vendor-class readers fitted to ThinkPads (X1 Carbon /
X1 Yoga gen 3 and later, T480/T490, P52s and relatives).

It depends on **libusb-1.0 and libc only**. No libfprint, no fprintd, no
D-Bus, no polkit, no Python, no kernel module, no systemd unit. It builds
with `make` on any Linux or BSD system that has libusb, and the PAM module
drops into any PAM stack.

## Why this exists

These sensors do all the matching on the chip; the host never sees a
fingerprint image. Communication is a Synaptics-specific two-layer protocol
over four USB endpoints, which is why the sensor is inert without a driver
that speaks it. This is a fresh implementation of that protocol.

## Building

```sh
make
```

Dependencies: a C compiler, `make`, `pkg-config`, `libusb-1.0` headers, and
(for the PAM module) PAM headers.

| Distribution  | Packages                                                             |
|---------------|----------------------------------------------------------------------|
| Debian/Ubuntu | `build-essential pkg-config libusb-1.0-0-dev libpam0g-dev`            |
| Fedora/RHEL   | `gcc make pkgconf-pkg-config libusb1-devel pam-devel`                 |
| Arch          | `base-devel libusb pam`                                              |
| openSUSE      | `gcc make pkg-config libusb-1_0-devel pam-devel`                      |
| Alpine        | `build-base pkgconf libusb-dev linux-pam-dev`                         |
| Void          | `base-devel pkg-config libusb-devel pam-devel`                        |

## Installing

```sh
./dist/install.sh              # or: sudo make install
```

This installs `synafp`, `libsynafp.so`, `synafp.h`, `pam_synafp.so` and a
udev rule that hands the sensor to the user on the active local seat, so you
do not need root for day-to-day use.

`PREFIX`, `BINDIR`, `LIBDIR`, `PAMDIR`, `UDEVDIR` and `DESTDIR` are all
honoured, so distro packaging is straightforward.

## Using it

```sh
synafp info                    # sensor identity, firmware, storage use
synafp enroll right-index      # record a finger (touch repeatedly when asked)
synafp verify                  # check a finger against your templates
synafp list                    # what is stored on the sensor
synafp delete right-index      # remove one finger
synafp clear                   # wipe the sensor's template store
```

Finger names are `left-thumb … left-little` and `right-thumb … right-little`
(numbers 1–10 also work). Exit status is `0` on success, `2` on a clean
non-match, `1` on error.

Useful global options: `-u <user>` to act on another user id, `-t <seconds>`
to bound how long the sensor waits for a finger, `-r` to USB-reset a wedged
sensor, and `-v` / `-vv` for protocol tracing.

Templates live in the sensor's own flash, keyed by the user id string, so
there is no host-side database to back up, corrupt, or keep in sync.
Capacity is typically ten fingers.

## PAM integration

Add the module *above* your password module. On Debian/Ubuntu edit
`/etc/pam.d/common-auth`; on Fedora/RHEL `/etc/pam.d/system-auth`; on Arch
`/etc/pam.d/system-local-login` (and `sudo`, `polkit-1`, your screen locker,
etc. as you like):

```
auth  sufficient  pam_synafp.so  timeout=15 retries=3
auth  include     system-auth
```

Module options:

| Option       | Meaning                                                   |
|--------------|-----------------------------------------------------------|
| `timeout=N`  | seconds to wait for a finger before giving up (default 15)|
| `retries=N`  | touches allowed before falling through (default 3)        |
| `quiet`      | suppress informational messages                           |
| `debug`      | log protocol detail to syslog                             |

The module returns `PAM_IGNORE` — not an error — whenever fingerprint auth
is merely *unavailable*: no sensor, no enrolled finger for this user, no
permission, or the user pressed Ctrl-C instead of touching the reader. A
`sufficient` line therefore falls through to the password prompt rather than
locking you out. Only an actual mismatch produces `PAM_AUTH_ERR`.

> Test a new PAM configuration in a second terminal while the first stays
> logged in as root. A broken auth stack is much easier to fix that way.

## Using the library

```c
#include <synafp.h>

syna_dev *d;
syna_match m;

if (syna_open(&d, NULL, 0) == SYNA_OK) {
    if (syna_verify(d, "alice", &m, NULL, NULL) == SYNA_OK && m.matched)
        puts("welcome");
    syna_close(d);
}
```

Link with `-lsynafp`. Every call returns `SYNA_OK` (0) or a negative code;
`syna_strerror()` renders it, including sensor-reported statuses.

## The protocol, briefly

Two nested layers over the sensor's bulk endpoints:

```
FW layer      EP 0x01 OUT / 0x81 IN
  request     [fw_cmd] ...
  reply       [status:u16le] ...

BMKT layer    carried inside FW command 0xA7
  message     [0xFE][seq][msg_id][payload_len][payload...]
```

A command is sent once; long-running operations (enrolment, matching) then
emit a stream of responses. The sensor raises bit 2 of the first byte on
interrupt endpoint `0x83` to say another message is waiting, and the host
fetches it by issuing FW command `0xA8` and reading `0x81` again. Finger
touch and lift arrive as unsolicited `0x91` events at any point. Cancellation
is a `0x41` command on the running sequence number, answered with `0x42`.

`syna_run_op()` in `src/synafp_core.c` implements exactly that loop; the
operations in `src/synafp_ops.c` are response handlers plugged into it.

## Troubleshooting

**`permission denied opening the USB device`** — the udev rule is not active.
`sudo udevadm control --reload-rules && sudo udevadm trigger --subsystem-match=usb`,
then replug or reboot. Running `sudo synafp info` confirms the driver itself
works.

**`no supported Synaptics fingerprint sensor found`** — check `lsusb | grep 06cb`.
If the sensor is missing entirely it may be disabled in the BIOS
(Security → I/O Port Access → Fingerprint Reader).

**Sensor wedged after a Windows boot or a crashed client** — `synafp -r info`
forces a USB reset. `syna_open()` also resets and retries automatically when
its first probe fails.

**`this finger is already enrolled`** — the sensor still holds a template for
that user id and finger. `synafp list`, then `synafp delete <finger>`.

**Fingerprints enrolled under Windows** are stored in the same on-chip flash
under Windows' own user ids and cannot be reused. `synafp clear` frees the
slots.

**Conflicts with other stacks.** If `fprintd`, `python-validity` or
`open-fprintd` is running they will fight over the device. Stop and disable
them before using synafp:
`systemctl disable --now fprintd python3-validity open-fprintd`.

## Layout

```
src/synafp.h        public API and protocol constants
src/synafp_priv.h   internals shared across the library
src/synafp_core.c   USB transport, BMKT framing, command engine
src/synafp_ops.c    enrol / verify / identify / list / delete / info
src/synafp_cli.c    the synafp command
src/pam_synafp.c    PAM module
dist/70-synafp.rules
dist/install.sh
```

## Licence

LGPL-2.1-or-later. The protocol constants follow the BMKT command set
published by Synaptics in libfprint's driver, which is under the same
licence.
