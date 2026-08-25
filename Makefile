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
CFLAGS      ?= -O2 -g
# -MMD -MP makes every object depend on the headers it includes, so a struct
# change cannot leave stale objects with mismatched layouts.
ALL_CFLAGS  := -std=c99 $(WARN) $(CFLAGS) $(USB_CFLAGS) $(SSL_CFLAGS) -Isrc -MMD -MP \
               -DSYNA_STATEDIR=\"$(STATEDIR)\"
LDLIBS      := $(USB_LIBS) $(SSL_LIBS)

LIB_SRC     := src/synafp_core.c src/synafp_vcsfw.c src/synafp_tls.c \
               src/synafp_capture.c src/synafp_tables.c src/synafp_db.c src/synafp_enroll.c
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

pam_synafp.so: src/pam_synafp.lo $(LIB_PIC)
	$(CC) $(ALL_CFLAGS) -shared -o $@ $^ $(LDLIBS) -lpam

$(SONAME): $(LIB_PIC)
	$(CC) $(ALL_CFLAGS) -shared -Wl,-soname,$(SONAME) -o $@ $^ $(LDLIBS)
	ln -sf $(SONAME) libsynafp.so

# Generated with an absolute path so the module can be tested before install.
synafp-test: dist/synafp-test.in
	sed 's|@MODULE@|$(CURDIR)/pam_synafp.so|g' $< > $@

pamtest: tools/pamtest.c
	$(CC) $(ALL_CFLAGS) -o $@ $< -lpam

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
	install -d $(DESTDIR)$(DATADIR)/synafp
	install -m 0644 dist/synafp-pam-example $(DESTDIR)$(DATADIR)/synafp/pam-example
	@echo
	@echo "Installed. Reload udev and replug/rescan the sensor:"
	@echo "  udevadm control --reload-rules && udevadm trigger --subsystem-match=usb"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/synafp
	rm -f $(DESTDIR)$(LIBDIR)/$(SONAME) $(DESTDIR)$(LIBDIR)/libsynafp.so
	rm -f $(DESTDIR)$(INCLUDEDIR)/synafp.h
	rm -f $(DESTDIR)$(PAMDIR)/pam_synafp.so
	rm -f $(DESTDIR)$(UDEVDIR)/70-synafp.rules

DEPS := $(LIB_OBJ:.o=.d) $(LIB_PIC:.lo=.d) src/synafp_cli.d src/pam_synafp.d
-include $(DEPS)

clean:
	rm -f synafp pamtest synafp-test $(LIB_OBJ) $(LIB_PIC) src/*.o src/*.lo src/*.d \
	      libsynafp.so libsynafp.so.* pam_synafp.so

.PHONY: all install uninstall clean check pamtest
