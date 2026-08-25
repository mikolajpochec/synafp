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
pkg-config --exists libusb-1.0 || die "libusb-1.0 development files not found.
  Debian/Ubuntu : apt install libusb-1.0-0-dev libpam0g-dev build-essential pkg-config
  Fedora/RHEL   : dnf install libusb1-devel pam-devel gcc make pkgconf-pkg-config
  Arch          : pacman -S libusb pam base-devel
  openSUSE      : zypper install libusb-1_0-devel pam-devel gcc make pkg-config
  Alpine        : apk add libusb-dev linux-pam-dev build-base pkgconf"
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
echo "    synafp info"
echo "Then enrol a finger:"
echo "    synafp enroll right-index"
