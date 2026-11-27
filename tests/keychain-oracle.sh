#!/bin/bash
# keychain-oracle.sh [dist-dir]: plant a fake cookie through the store and check it lands only in the Keychain.
# PASS = no file under the store/repo/tmp holds it, no cookie* file, argv of `security` never held it, Keychain returns it.
# A fake Chrome then checks the throwaway login profile is deleted. Exit 0 PASS, 1 FAIL. Cleans up its Keychain item.
set -uo pipefail
D=$(cd "${1:-$(dirname "$0")/../dist}" && pwd); REPO=$(cd "$(dirname "$0")/.." && pwd)
V="FAKE""COOKIE_0123456789"; HOST=oracle.invalid; S="$HOME/Library/Application Support/overleaf-mcp"; SVC=${OL_KEYCHAIN_SERVICE:-overleaf-mcp}
SHIM=$(mktemp -d); trap 'rm -rf "$SHIM"; security delete-generic-password -s "$SVC" -a $HOST >/dev/null 2>&1' EXIT
printf '#!/bin/sh\necho "$@" >> %s/argv\nexec /usr/bin/security "$@"\n' "$SHIM" > "$SHIM/security"; chmod +x "$SHIM/security"
PATH="$SHIM:$PATH" OL_BASE_URL=https://$HOST node --input-type=module -e "
const s = await import('$D/auth/cookieStore.js'); await s.saveStored('https://$HOST', '$V');
const r = await s.loadStored('https://$HOST'); if (r?.cookie !== '$V') { console.error('load mismatch'); process.exit(1); }"
f=0; hex=$(printf %s "$V" | xxd -p)
hits=$(grep -rl "${V:0:15}" "$S" "$REPO" /tmp 2>/dev/null); [ -z "$hits" ] || { echo "FAIL: on disk: $hits"; f=1; }
c=$(find "$S" -name 'cookie*' 2>/dev/null); [ -z "$c" ] || { echo "FAIL: cookie file: $c"; f=1; }
grep -q find-generic "$SHIM/argv" 2>/dev/null && ! grep -qi -e "$V" -e "$hex" "$SHIM/argv" || { echo "FAIL: security argv unseen or holds the secret"; f=1; }
k=$(security find-generic-password -s "$SVC" -a $HOST -w 2>/dev/null); [[ $k == *"$V"* ]] || { echo "FAIL: Keychain lacks it"; f=1; }
# fake Chrome: writes a Cookies file + a dead DevTools port into its --user-data-dir, then waits to be killed
printf '#!/bin/sh\nfor a; do case $a in --user-data-dir=*) p=${a#*=};; esac; done\necho x > "$p/Cookies"; echo "$p" > %s/prof\nprintf "1\\n/x\\n" > "$p/DevToolsActivePort"\nexec sleep 30\n' "$SHIM" > "$SHIM/chrome"; chmod +x "$SHIM/chrome"
OL_BROWSER="$SHIM/chrome" node --input-type=module -e "
const b = await import('$D/auth/browserLogin.js'); await b.captureCookie('https://$HOST', { timeoutMs: 1000 }).catch(() => 0);" 2>/dev/null
p=$(cat "$SHIM/prof" 2>/dev/null); [ -n "$p" ] && [ ! -e "$p" ] || { echo "FAIL: Chrome profile left on disk: ${p:-none written}"; f=1; }
[ $f = 0 ] && echo PASS; exit $f
