#!/bin/sh
# Add synafp to an auth stack, reversibly.
#
#   sudo ./dist/enable-pam.sh            # detect the right file and edit it
#   sudo ./dist/enable-pam.sh --undo     # put it back
#   sudo ./dist/enable-pam.sh FILE       # edit a specific /etc/pam.d file
#
# The line is inserted as `sufficient`, above the password module, so a
# fingerprint can satisfy authentication but failing to use one falls through
# to the password prompt exactly as before.
#
# BEFORE RUNNING: open a second terminal and become root there (`sudo -i`).
# Keep it open until you have confirmed login still works. That root shell is
# what you fix a broken stack from.
set -eu

MODULE=pam_synafp.so
LINE="auth      sufficient pam_synafp.so   timeout=10 retries=2"
STAMP=$(date +%Y%m%d-%H%M%S)

die() { echo "enable-pam.sh: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run me with sudo"

undo=0
target=""
for a in "$@"; do
    case "$a" in
        --undo) undo=1 ;;
        -*)     die "unknown option $a" ;;
        *)      target="$a" ;;
    esac
done

# Which file covers login, the display manager and the screen locker without
# also covering sudo and su? It differs per distribution.
if [ -z "$target" ]; then
    for f in /etc/pam.d/system-login \
             /etc/pam.d/common-auth \
             /etc/pam.d/system-auth; do
        [ -f "$f" ] && { target="$f"; break; }
    done
fi
[ -n "$target" ] && [ -f "$target" ] || die "no auth stack found; pass one explicitly"

if [ "$undo" -eq 1 ]; then
    grep -q "$MODULE" "$target" || die "$target does not mention $MODULE"
    cp -a "$target" "$target.synafp-undo-$STAMP"
    grep -v "$MODULE" "$target" > "$target.tmp"
    mv "$target.tmp" "$target"
    chmod 644 "$target"
    echo "Removed $MODULE from $target"
    echo "Previous contents saved as $target.synafp-undo-$STAMP"
    exit 0
fi

# A dangling module reference makes every login attempt fail, so check first.
found=""
for d in /lib/security /usr/lib/security /usr/lib64/security \
         /usr/lib/x86_64-linux-gnu/security; do
    [ -f "$d/$MODULE" ] && { found="$d/$MODULE"; break; }
done
[ -n "$found" ] || die "$MODULE is not installed. Run 'sudo make install' first."

if grep -q "$MODULE" "$target"; then
    echo "$target already references $MODULE; nothing to do."
    exit 0
fi

cp -a "$target" "$target.synafp-backup-$STAMP"

# Insert above the first line that delegates or does the password check, so
# the fingerprint is offered first and the password remains the fallback.
awk -v line="$LINE" '
    !done && $1 == "auth" && ($2 == "include" || $2 == "substack" || /pam_unix\.so/) {
        print line; done = 1
    }
    { print }
    END { if (!done) print line }
' "$target.synafp-backup-$STAMP" > "$target.tmp"

mv "$target.tmp" "$target"
chmod 644 "$target"

echo "Added to $target:"
echo "    $LINE"
echo
echo "Backup: $target.synafp-backup-$STAMP"
echo
echo "Now, WITHOUT closing your root shell, verify in another terminal:"
echo "    sudo ./pamtest"
echo "    su - $(logname 2>/dev/null || echo YOURUSER)"
echo
echo "If anything misbehaves, undo it with:"
echo "    sudo $0 --undo"
