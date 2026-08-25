#!/bin/sh
# synafp installer - deliberately POSIX sh and distro-agnostic.
#
#   ./dist/install.sh            build and install under /usr/local
#   PREFIX=/usr ./dist/install.sh
#
set -eu

PREFIX="${PREFIX:-/usr/local}"
SRCDIR="$(cd "$(dirname "$0")/.." && pwd)"

die() { echo "install.sh: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

echo "==> checking build dependencies"
have "${CC:-cc}" || have gcc || have clang || die "no C compiler found (install gcc or clang)"
have make        || die "make not found"
have pkg-config  || die "pkg-config not found"
DEPS_HELP="
  Debian/Ubuntu : apt install build-essential pkg-config libusb-1.0-0-dev libssl-dev libpam0g-dev
  Fedora/RHEL   : dnf install gcc make pkgconf-pkg-config libusb1-devel openssl-devel pam-devel
  Arch          : pacman -S base-devel libusb openssl pam
  openSUSE      : zypper install gcc make pkg-config libusb-1_0-devel libopenssl-devel pam-devel
  Alpine        : apk add build-base pkgconf libusb-dev openssl-dev linux-pam-dev
  Void          : xbps-install base-devel pkg-config libusb-devel openssl-devel pam-devel"

pkg-config --exists libusb-1.0 || die "libusb-1.0 development files not found.$DEPS_HELP"
pkg-config --exists libcrypto  || die "OpenSSL development files not found.$DEPS_HELP"
[ -f /usr/include/security/pam_modules.h ] || \
  echo "install.sh: warning: PAM headers not found; pam_synafp.so may fail to build"

echo "==> building"
make -C "$SRCDIR" clean >/dev/null 2>&1 || true
make -C "$SRCDIR"

echo "==> installing to $PREFIX (needs root)"
if [ "$(id -u)" -eq 0 ]; then
    make -C "$SRCDIR" PREFIX="$PREFIX" install
else
    have sudo || die "not root and sudo is unavailable; re-run this script as root"
    sudo make -C "$SRCDIR" PREFIX="$PREFIX" install
fi

echo "==> reloading udev"
if have udevadm; then
    if [ "$(id -u)" -eq 0 ]; then
        udevadm control --reload-rules && udevadm trigger --subsystem-match=usb
    else
        sudo udevadm control --reload-rules && sudo udevadm trigger --subsystem-match=usb
    fi
else
    echo "no udevadm; grant access to the device node yourself, or run synafp as root"
fi

echo
echo "Done. Verify with:"
echo "    sudo synafp info"
echo
echo "Most commands need root: the TLS session key derives from the DMI"
echo "product serial, which only root can read."
echo
echo "Per-line calibration data is required before the sensor will detect a"
echo "finger, and synafp cannot generate it yet. If python-validity has run"
echo "on this machine, import what it produced:"
echo "    sudo synafp calib-import /var/run/python-validity/calib-data.bin"
echo
echo "Then enrol a finger:"
echo "    sudo synafp enroll right-index"
