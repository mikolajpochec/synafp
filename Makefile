# synafp - portable userspace driver for Synaptics match-on-chip fingerprint sensors
#
# Plain POSIX make + pkg-config. No meson, no cmake, no distro packaging needed.
#
#   make                 build the CLI, the shared library and the PAM module
#   make install         install into $(PREFIX) (default /usr/local) + udev rule
#   make uninstall
#   make install-pam     also wire the module into the local PAM stack helper
#
PREFIX      ?= /usr/local
BINDIR      ?= $(PREFIX)/bin
LIBDIR      ?= $(PREFIX)/lib
INCLUDEDIR  ?= $(PREFIX)/include
UDEVDIR     ?= /usr/lib/udev/rules.d
PAMDIR      ?= $(shell test -d /lib/security && echo /lib/security || \
                        (test -d /usr/lib64/security && echo /usr/lib64/security || \
                         echo /usr/lib/security))
DESTDIR     ?=

CC          ?= cc
PKG_CONFIG  ?= pkg-config

USB_CFLAGS  := $(shell $(PKG_CONFIG) --cflags libusb-1.0)
USB_LIBS    := $(shell $(PKG_CONFIG) --libs libusb-1.0)

WARN        := -Wall -Wextra -Wno-unused-parameter
CFLAGS      ?= -O2 -g
ALL_CFLAGS  := -std=c99 $(WARN) $(CFLAGS) $(USB_CFLAGS) -Isrc
LDLIBS      := $(USB_LIBS)

LIB_SRC     := src/synafp_core.c src/synafp_ops.c
LIB_OBJ     := $(LIB_SRC:.c=.o)
LIB_PIC     := $(LIB_SRC:.c=.lo)

SOVER       := 1
SONAME      := libsynafp.so.$(SOVER)

all: synafp $(SONAME) pam_synafp.so

%.o: %.c
	$(CC) $(ALL_CFLAGS) -c $< -o $@

%.lo: %.c
	$(CC) $(ALL_CFLAGS) -fPIC -c $< -o $@

synafp: src/synafp_cli.o $(LIB_OBJ)
	$(CC) $(ALL_CFLAGS) -o $@ $^ $(LDLIBS)

$(SONAME): $(LIB_PIC)
	$(CC) $(ALL_CFLAGS) -shared -Wl,-soname,$(SONAME) -o $@ $^ $(LDLIBS)
	ln -sf $(SONAME) libsynafp.so

pam_synafp.so: src/pam_synafp.lo $(LIB_PIC)
	$(CC) $(ALL_CFLAGS) -shared -o $@ $^ $(LDLIBS) -lpam

check: synafp
	./synafp --help >/dev/null && echo "smoke test ok"

install: all
	install -d $(DESTDIR)$(BINDIR) $(DESTDIR)$(LIBDIR) $(DESTDIR)$(INCLUDEDIR)
	install -m 0755 synafp        $(DESTDIR)$(BINDIR)/synafp
	install -m 0755 $(SONAME)     $(DESTDIR)$(LIBDIR)/$(SONAME)
	ln -sf $(SONAME)              $(DESTDIR)$(LIBDIR)/libsynafp.so
	install -m 0644 src/synafp.h  $(DESTDIR)$(INCLUDEDIR)/synafp.h
	install -d $(DESTDIR)$(PAMDIR)
	install -m 0755 pam_synafp.so $(DESTDIR)$(PAMDIR)/pam_synafp.so
	install -d $(DESTDIR)$(UDEVDIR)
	install -m 0644 dist/70-synafp.rules $(DESTDIR)$(UDEVDIR)/70-synafp.rules
	@echo
	@echo "Installed. Reload udev and replug/rescan the sensor:"
	@echo "  udevadm control --reload-rules && udevadm trigger --subsystem-match=usb"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/synafp
	rm -f $(DESTDIR)$(LIBDIR)/$(SONAME) $(DESTDIR)$(LIBDIR)/libsynafp.so
	rm -f $(DESTDIR)$(INCLUDEDIR)/synafp.h
	rm -f $(DESTDIR)$(PAMDIR)/pam_synafp.so
	rm -f $(DESTDIR)$(UDEVDIR)/70-synafp.rules

clean:
	rm -f synafp $(LIB_OBJ) $(LIB_PIC) src/*.o src/*.lo \
	      libsynafp.so libsynafp.so.* pam_synafp.so

.PHONY: all install uninstall clean check
