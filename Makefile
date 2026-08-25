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
DATADIR     ?= $(PREFIX)/share
LIBEXECDIR  ?= $(PREFIX)/libexec
STATEDIR    ?= /var/lib/synafp
PAMDIR      ?= $(shell test -d /lib/security && echo /lib/security || \
                        (test -d /usr/lib64/security && echo /usr/lib64/security || \
                         echo /usr/lib/security))
DESTDIR     ?=

CC          ?= cc
PKG_CONFIG  ?= pkg-config

USB_CFLAGS  := $(shell $(PKG_CONFIG) --cflags libusb-1.0)
USB_LIBS    := $(shell $(PKG_CONFIG) --libs libusb-1.0)
SSL_CFLAGS  := $(shell $(PKG_CONFIG) --cflags libcrypto)
SSL_LIBS    := $(shell $(PKG_CONFIG) --libs libcrypto)

WARN        := -Wall -Wextra -Wno-unused-parameter

# This code runs privileged and parses input from a peripheral, so the usual
# hardening is not optional. Override HARDEN= to disable for debugging.
HARDEN      ?= -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE
HARDEN_LD   ?= -Wl,-z,relro,-z,now -Wl,-z,noexecstack -pie
CFLAGS      ?= -O2 -g
# -MMD -MP makes every object depend on the headers it includes, so a struct
# change cannot leave stale objects with mismatched layouts.
ALL_CFLAGS  := -std=c99 $(WARN) $(HARDEN) $(CFLAGS) $(USB_CFLAGS) $(SSL_CFLAGS) -Isrc \
               -MMD -MP -DSYNA_STATEDIR=\"$(STATEDIR)\" \
               -DSYNAFP_HELPER=\"$(LIBEXECDIR)/synafp-auth\"
LDLIBS      := $(USB_LIBS) $(SSL_LIBS)

LIB_SRC     := src/synafp_core.c src/synafp_vcsfw.c src/synafp_tls.c \
               src/synafp_capture.c src/synafp_tables.c src/synafp_db.c src/synafp_enroll.c \
               src/synafp_calib.c
LIB_OBJ     := $(LIB_SRC:.c=.o)
LIB_PIC     := $(LIB_SRC:.c=.lo)

SOVER       := 1
SONAME      := libsynafp.so.$(SOVER)

all: synafp synafp-auth $(SONAME) pam_synafp.so

%.o: %.c
	$(CC) $(ALL_CFLAGS) -c $< -o $@

%.lo: %.c
	$(CC) $(ALL_CFLAGS) -fPIC -c $< -o $@

synafp: src/synafp_cli.o $(LIB_OBJ)
	$(CC) $(ALL_CFLAGS) $(HARDEN_LD) -o $@ $^ $(LDLIBS)

synafp-auth: src/synafp_auth.o $(LIB_OBJ)
	$(CC) $(ALL_CFLAGS) $(HARDEN_LD) -o $@ $^ $(LDLIBS)

pam_synafp.so: src/pam_synafp.lo $(LIB_PIC)
	$(CC) $(ALL_CFLAGS) -shared -o $@ $^ $(LDLIBS) -lpam

$(SONAME): $(LIB_PIC)
	$(CC) $(ALL_CFLAGS) -shared -Wl,-soname,$(SONAME) -o $@ $^ $(LDLIBS)
	ln -sf $(SONAME) libsynafp.so

# Generated with an absolute path so the module can be tested before install.
synafp-test: dist/synafp-test.in
	sed 's|@MODULE@|$(CURDIR)/pam_synafp.so|g' $< > $@

fuzzparse: tools/fuzzparse.c $(LIB_OBJ)
	$(CC) $(ALL_CFLAGS) -o $@ $^ $(LDLIBS)

pamtest: tools/pamtest.c
	$(CC) $(ALL_CFLAGS) -o $@ $< -lpam

check: synafp
	./synafp --help >/dev/null && echo "smoke test ok"

install: all
	install -d $(DESTDIR)$(BINDIR) $(DESTDIR)$(LIBDIR) $(DESTDIR)$(INCLUDEDIR)
	install -m 0755 synafp        $(DESTDIR)$(BINDIR)/synafp
	install -d $(DESTDIR)$(LIBEXECDIR)
	# setuid: screen lockers authenticate as the locked-out user and cannot
	# reach the DMI serial themselves.
	install -m 4755 synafp-auth   $(DESTDIR)$(LIBEXECDIR)/synafp-auth
	install -m 0755 $(SONAME)     $(DESTDIR)$(LIBDIR)/$(SONAME)
	ln -sf $(SONAME)              $(DESTDIR)$(LIBDIR)/libsynafp.so
	install -m 0644 src/synafp.h  $(DESTDIR)$(INCLUDEDIR)/synafp.h
	install -d $(DESTDIR)$(PAMDIR)
	install -m 0755 pam_synafp.so $(DESTDIR)$(PAMDIR)/pam_synafp.so
	install -d $(DESTDIR)$(UDEVDIR)
	install -m 0644 dist/70-synafp.rules $(DESTDIR)$(UDEVDIR)/70-synafp.rules
	install -d $(DESTDIR)$(DATADIR)/synafp
	install -m 0644 dist/synafp-pam-example $(DESTDIR)$(DATADIR)/synafp/pam-example
	@echo
	@echo "Installed. Reload udev (note: sudo on BOTH commands):"
	@echo "  sudo udevadm control --reload-rules"
	@echo "  sudo udevadm trigger --subsystem-match=usb"
	@echo
	@echo "Then wire it into login and the screen locker:"
	@echo "  sudo ./dist/enable-pam.sh"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/synafp
	rm -f $(DESTDIR)$(LIBEXECDIR)/synafp-auth
	rm -f $(DESTDIR)$(LIBDIR)/$(SONAME) $(DESTDIR)$(LIBDIR)/libsynafp.so
	rm -f $(DESTDIR)$(INCLUDEDIR)/synafp.h
	rm -f $(DESTDIR)$(PAMDIR)/pam_synafp.so
	rm -f $(DESTDIR)$(UDEVDIR)/70-synafp.rules

DEPS := $(LIB_OBJ:.o=.d) $(LIB_PIC:.lo=.d) src/synafp_cli.d src/pam_synafp.d \
        src/synafp_auth.d
-include $(DEPS)

clean:
	rm -f synafp synafp-auth pamtest fuzzparse synafp-test $(LIB_OBJ) $(LIB_PIC) src/*.o src/*.lo src/*.d \
	      libsynafp.so libsynafp.so.* pam_synafp.so

.PHONY: all install uninstall clean check pamtest
