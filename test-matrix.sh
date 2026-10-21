#!/bin/bash

# ====================================================
#  Cove Release Test Matrix
#  Description: Drives the Incus distro containers on the test box through
#               the pre-release checklist and renders a distro × check table.
#
#  Usage:
#    ./test-matrix.sh              # compile, deploy, run, wait, report
#    ./test-matrix.sh --async     # compile, deploy, launch, return immediately
#    ./test-matrix.sh report      # render the table for the current/last run
#    ./test-matrix.sh --no-compile ...   # skip ./compile.sh (use cove.sh as-is)
#
#  The box (override with COVE_TEST_BOX) hosts six Incus containers, each with
#  a "baseline" snapshot (clean OS + curl). Lanes:
#    A (all six):      fresh --dev install → add/clone/rename/login/delete →
#                      a login link rewriting a live-domain home →
#                      status/health/mailpit → mail from a page and WP-CLI →
#                      `cove mcp` over stdio → Laravel sites (SQLite and
#                      MariaDB, artisan, one-time login, clone, delete) →
#                      log rotation settings →
#                      container reboot survival
#    B (one apt/dnf):  previous GitHub release → candidate + post-upgrade
#    C (one apt/dnf):  install + add as a non-root sudo user →
#                      the previous release's own `cove upgrade` to the
#                      candidate, as that user
# ====================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# The test box is deliberately not committed — set COVE_TEST_BOX in the
# environment, or put the SSH target (e.g. root@testbox.example.com) in an
# untracked .test-box file next to this script.
BOX="${COVE_TEST_BOX:-}"
if [ -z "$BOX" ] && [ -f "$SCRIPT_DIR/.test-box" ]; then
    BOX="$(head -1 "$SCRIPT_DIR/.test-box")"
fi
if [ -z "$BOX" ]; then
    echo "❌ No test box configured. Set COVE_TEST_BOX or create $SCRIPT_DIR/.test-box"
    exit 1
fi
REMOTE_DIR="/root/cove-tests"

COMPILE=true
ASYNC=false
ACTION="run"
for arg in "$@"; do
    case "$arg" in
        --no-compile) COMPILE=false ;;
        --async)      ASYNC=true ;;
        report)       ACTION="report" ;;
        up)           ACTION="up" ;;
        down)         ACTION="down" ;;
    esac
done

# up/down: manual fleet control. A run spins containers up automatically
# (the restore step starts them); a fully green run parks them again. These
# exist for poking at containers outside a run, and for parking after
# debugging a failure.
if [ "$ACTION" = "up" ]; then
    ssh "$BOX" "incus start \$(incus list -c n -f csv | grep '^cove-') 2>/dev/null; incus list -c ns -f compact"
    exit 0
elif [ "$ACTION" = "down" ]; then
    ssh "$BOX" "incus stop -f \$(incus list -c n -f csv | grep '^cove-') 2>/dev/null; incus list -c ns -f compact"
    exit 0
fi

render_report() {
    local raw
    raw=$(ssh "$BOX" "cat $REMOTE_DIR/matrix/results.txt 2>/dev/null; [ -f $REMOTE_DIR/matrix/DONE ] && echo '__DONE__'; [ -f $REMOTE_DIR/matrix/PARKED ] && echo '__PARKED__'")
    if [ -z "$raw" ]; then
        echo "No matrix results found on $BOX — has a run been started?"
        exit 2
    fi
    local done_flag=false
    grep -q '__DONE__' <<<"$raw" && done_flag=true

    echo "$raw" | grep '^CHECK|' | awk -F'|' '
    {
        c=$2; sub(/^cove-/, "", c)
        checks[$3]; conts[c]; v[$3,c]=$4
        if (!($3 in ord)) ord[$3]=++n
    }
    END {
        nc=0; for (co in conts) cols[++nc]=co
        # stable column order
        split("ubuntu2404 ubuntu2204 debian12 debian13 fedora43 rocky9", want, " ")
        printf "%-18s", "check"
        for (i=1;i<=6;i++) if (want[i] in conts) printf "%-12s", want[i]
        print ""
        for (k=1;k<=n;k++) {
            for (ch in ord) if (ord[ch]==k) name=ch
            printf "%-18s", name
            for (i=1;i<=6;i++) {
                if (!(want[i] in conts)) continue
                r=v[name,want[i]]
                s=(r=="PASS") ? "✓" : (r=="FAIL") ? "✗ FAIL" : (r=="SKIP") ? "–" : "…"
                printf "%-12s", s
            }
            print ""
        }
    }'

    local fails
    fails=$(grep -c '|FAIL$' <<<"$raw" || true)
    echo ""
    if ! $done_flag; then
        echo "⏳ Run still in progress ('…' = no result yet). Logs: $BOX:$REMOTE_DIR/matrix/*.log"
        exit 2
    elif [ "$fails" -gt 0 ]; then
        echo "❌ $fails check(s) failed. Containers left RUNNING for inspection —"
        echo "   logs: $BOX:$REMOTE_DIR/matrix/*.log · park when done: ./test-matrix.sh down"
        exit 1
    else
        if grep -q '__PARKED__' <<<"$raw"; then
            echo "✅ All checks passed. Fleet parked (containers stopped)."
        else
            echo "✅ All checks passed."
        fi
        exit 0
    fi
}

if [ "$ACTION" = "report" ]; then
    render_report
fi

# --- Build ---
if $COMPILE; then
    ( cd "$SCRIPT_DIR" && ./compile.sh >/dev/null )
fi
bash -n "$SCRIPT_DIR/cove.sh" || { echo "❌ cove.sh failed syntax check"; exit 1; }

# --- The box-side runner ---
RUNNER=$(mktemp)
cat > "$RUNNER" <<'RUNNER_EOF'
#!/bin/bash
# Box-side matrix runner (generated by test-matrix.sh — do not edit on the box).
D=/root/cove-tests/matrix
SRC=/root/cove-tests
rm -rf "$D"; mkdir -p "$D"

CONTAINERS="cove-ubuntu2404 cove-ubuntu2204 cove-debian12 cove-debian13 cove-fedora43 cove-rocky9"
UPGRADE_LANE="cove-ubuntu2404 cove-rocky9"
SUDO_LANE="cove-debian12 cove-fedora43"

res() { echo "CHECK|$1|$2|$3" >> "$D/results.txt"; }

restore() {
    local c=$1
    incus stop -f "$c" 2>/dev/null
    incus snapshot restore "$c" baseline
    incus start "$c"
    sleep 10
}

cx() { local c=$1; shift; timeout 600 incus exec "$c" -- "$@"; }

# Site checks retry a few times — a curl fired immediately after a Caddy
# reload (add/clone/rename all trigger one) can race the reload and see a
# transient failure that isn't a product bug.
http_code() { # container host -> http status of https://host.localhost/
    local code i
    for i in 1 2 3 4; do
        code=$(incus exec "$1" -- curl -sk -o /dev/null -w '%{http_code}' --max-time 20 "https://$2.localhost/")
        [ "$code" = "200" ] && break
        sleep 3
    done
    echo "$code"
}

site_has() { # container host needle
    local i
    for i in 1 2 3 4; do
        if incus exec "$1" -- curl -sk --max-time 20 "https://$2.localhost/" | grep -q "$3"; then
            return 0
        fi
        sleep 3
    done
    return 1
}

lane_a() {
    local c=$1 L="$D/$c.log"
    {
        restore "$c"
        incus file push "$SRC/cove.sh" "$c/root/cove.sh"
        incus file push "$SRC/install-cove.sh" "$c/root/install-cove.sh"

        if cx "$c" bash /root/install-cove.sh --dev && cx "$c" cove version | grep -q "Cove version"; then
            res "$c" install PASS
        else
            res "$c" install FAIL
            for k in add_latest add_pinned add_plain add_from clone rename login login_rewrite delete status health mailpit mail mcp laravel logrotate reboot uninstall; do res "$c" "$k" SKIP; done
            return
        fi

        if cx "$c" cove add alpha && site_has "$c" alpha "Welcome to alpha"; then
            res "$c" add_latest PASS
        else
            res "$c" add_latest FAIL
        fi

        if cx "$c" cove add beta 6.4.3 && cx "$c" grep -q "6.4.3" /root/Cove/Sites/beta.localhost/public/wp-includes/version.php; then
            res "$c" add_pinned PASS
        else
            res "$c" add_pinned FAIL
        fi

        if cx "$c" cove add gamma plain && [ "$(http_code "$c" gamma)" = "200" ]; then
            res "$c" add_plain PASS
        else
            res "$c" add_plain FAIL
        fi

        # `cove add --from` with an archive: a .tar.gz whose files sit in one
        # folder (stripped), a .zip (Cove's ZipArchive fallback where there's
        # no unzip), one with ../ in it (refused, nothing made), and a clone
        # that keeps the whole project, not just public/.
        if cx "$c" bash -s <<'ADDFROM'
fail() { echo "add_from: $*" >&2; exit 1; }
d=$(mktemp -d); mkdir -p "$d/app/public"
echo '<?php echo "from ok";' > "$d/app/public/index.php"; echo tool > "$d/app/tool"
tar -czf "$d/app.tar.gz" -C "$d" app || fail "making the tarball"
cove add fromt --from="$d/app.tar.gz" >/tmp/from.log 2>&1 || fail "cove add (tar.gz): $(tail -n 5 /tmp/from.log)"
[ -f /root/Cove/Sites/fromt.localhost/tool ] || fail "the archive's top folder was not stripped"
grep -q '^kind=archive' /root/Cove/Sites/fromt.localhost/cove-from || fail "no cove-from"
[ "$(curl -sk --max-time 20 https://fromt.localhost/)" = "from ok" ] || fail "fromt does not serve its public/"
mkzip() { if command -v python3 >/dev/null; then python3 -c "import sys, zipfile; z = zipfile.ZipFile(sys.argv[1], 'w'); z.writestr(sys.argv[2], sys.argv[3]); z.close()" "$@"; else COVE_Z="$1" COVE_N="$2" COVE_C="$3" frankenphp php-cli -r '$z = new ZipArchive(); $z->open(getenv("COVE_Z"), ZipArchive::CREATE); $z->addFromString(getenv("COVE_N"), getenv("COVE_C")); exit($z->close() ? 0 : 1);'; fi; }
mkzip "$d/s.zip" index.html "zip ok" || fail "making the zip"
cove add fromz --from="$d/s.zip" >/tmp/fromz.log 2>&1 || fail "cove add (zip): $(tail -n 5 /tmp/fromz.log)"
[ "$(curl -sk --max-time 20 https://fromz.localhost/)" = "zip ok" ] || fail "fromz does not serve the zip's index.html"
mkzip "$d/evil.zip" ../evil.txt x || fail "making the bad zip"
if cove add frome --from="$d/evil.zip" >/tmp/frome.log 2>&1; then fail "a zip with ../ was accepted"; fi
[ ! -e /root/Cove/Sites/frome.localhost ] || fail "the refused zip left a site"
[ ! -e /root/Cove/Sites/evil.txt ] || fail "the refused zip wrote outside its folder"
cove clone fromt fromt2 >/dev/null 2>&1 || fail "cove clone"
[ -f /root/Cove/Sites/fromt2.localhost/tool ] || fail "the clone left out the project outside public/"
for s in fromt fromt2 fromz; do cove delete "$s" --force >/dev/null 2>&1 || fail "cove delete $s"; done
exit 0
ADDFROM
        then
            res "$c" add_from PASS
        else
            res "$c" add_from FAIL
        fi

        if cx "$c" cove clone alpha alpha2 && site_has "$c" alpha2 "Welcome to"; then
            res "$c" clone PASS
        else
            res "$c" clone FAIL
        fi

        if cx "$c" cove rename gamma delta && [ "$(http_code "$c" delta)" = "200" ] && ! cx "$c" test -d /root/Cove/Sites/gamma.localhost; then
            res "$c" rename PASS
        else
            res "$c" rename FAIL
        fi

        if cx "$c" bash -c 'url=$(cove login alpha 2>/dev/null | grep -oE "https://[^ \"]*cove_login_token=[A-Za-z0-9]+" | head -1); [ -n "$url" ] && curl -skL --max-time 20 -c /tmp/jar "$url" -o /dev/null && grep -q wordpress_logged_in /tmp/jar'; then
            res "$c" login PASS
        else
            res "$c" login FAIL
        fi

        # A site whose stored URLs still name a live domain: asking for a
        # login link rewrites them first (database saved to private/), and
        # the link signs in here. A second link has nothing to rewrite.
        if cx "$c" bash -s <<'LOGINREWRITE'
fail() { echo "login_rewrite: $*" >&2; exit 1; }
cove wp alpha option update home https://www.example.com >/dev/null 2>&1 || fail "setting home"
cove wp alpha option update siteurl https://www.example.com >/dev/null 2>&1 || fail "setting siteurl"
cove wp alpha option update cove_matrix_hosts 'https://www.example.com.au/x https://www.example.com/y' >/dev/null 2>&1 || fail "setting cove_matrix_hosts"
link=$(cove login alpha --plain 2>/tmp/rewrite.err) || fail "cove login: $(cat /tmp/rewrite.err)"
echo "$link" | grep -Eq '^https://alpha\.localhost(:[0-9]+)?/wp-login\.php\?' || fail "link is $link"
grep -q 'Rewriting them to https://alpha.localhost' /tmp/rewrite.err || fail "no rewrite message: $(cat /tmp/rewrite.err)"
cove wp alpha option get home 2>/dev/null | grep -Eqx 'https://alpha\.localhost(:[0-9]+)?' || fail "home not rewritten"
cove wp alpha option get siteurl 2>/dev/null | grep -Eqx 'https://alpha\.localhost(:[0-9]+)?' || fail "siteurl not rewritten"
ls /root/Cove/Sites/alpha.localhost/private/database-before-url-rewrite-*.sql >/dev/null 2>&1 || fail "no database copy in private/"
hosts=$(cove wp alpha option get cove_matrix_hosts 2>/dev/null)
echo "$hosts" | grep -Eqx 'https://www\.example\.com\.au/x https://alpha\.localhost(:[0-9]+)?/y' || fail "a longer host was rewritten too: $hosts"
curl -skL --max-time 20 -c /tmp/jar-rewrite "$link" -o /dev/null || fail "link did not load"
grep -q wordpress_logged_in /tmp/jar-rewrite || fail "link did not sign in"
cove login alpha --plain >/dev/null 2>/tmp/rewrite2.err || fail "second login"
if grep -q Rewriting /tmp/rewrite2.err; then fail "second login rewrote again"; fi
exit 0
LOGINREWRITE
        then
            res "$c" login_rewrite PASS
        else
            res "$c" login_rewrite FAIL
        fi

        if cx "$c" cove delete alpha2 && ! cx "$c" test -d /root/Cove/Sites/alpha2.localhost; then
            res "$c" delete PASS
        else
            res "$c" delete FAIL
        fi

        if cx "$c" cove status >/dev/null; then res "$c" status PASS; else res "$c" status FAIL; fi
        if cx "$c" cove health >/dev/null; then res "$c" health PASS; else res "$c" health FAIL; fi

        # Through Caddy, which supplies Mailpit's web UI password; the bare
        # port must refuse a request that has none (DNS-rebinding guard).
        if cx "$c" curl -sk --max-time 10 https://mail.cove.localhost/api/v1/messages | grep -q "total\|messages\|\[" \
            && [ "$(cx "$c" curl -s -o /dev/null -w '%{http_code}' --max-time 10 http://127.0.0.1:8025/api/v1/messages)" = "401" ]; then
            res "$c" mailpit PASS
        else
            res "$c" mailpit FAIL
        fi

        # Mail reaches Mailpit from a page and from WP-CLI. Both go through
        # Cove's sendmail wrapper (FrankenPHP's php_ini, and ~/Cove/php.ini
        # for the CLI), which nothing above exercises.
        if cx "$c" bash -s <<'MAILCHECK'
set -e
pub=/root/Cove/Sites/alpha.localhost/public
cove wp alpha eval 'wp_mail("cli@matrix.test", "matrix cli", "x");' >/dev/null 2>&1
printf '%s\n' '<?php require __DIR__ . "/wp-load.php"; echo wp_mail("web@matrix.test", "matrix web", "x") ? "sent" : "failed";' > "$pub/matrix-mail.php"
curl -sk --max-time 30 https://alpha.localhost/matrix-mail.php | grep -q sent
rm -f "$pub/matrix-mail.php"
for i in 1 2 3 4 5 6; do
    r=$(curl -sk --max-time 10 "https://mail.cove.localhost/api/v1/search?query=matrix")
    if echo "$r" | grep -q "matrix cli" && echo "$r" | grep -q "matrix web"; then exit 0; fi
    sleep 2
done
exit 1
MAILCHECK
        then
            res "$c" mail PASS
        else
            res "$c" mail FAIL
        fi

        # `cove mcp` speaks MCP on stdio through FrankenPHP's php-cli: one
        # session that initializes, lists a site and runs WP-CLI in it.
        if cx "$c" bash -s <<'MCPCHECK'
out=$(printf '%s\n' \
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"matrix","version":"0"}}}' \
    '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
    '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_sites","arguments":{"filter":"alpha"}}}' \
    '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"wp","arguments":{"site":"alpha","args":["option","get","siteurl"]}}}' \
    '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"wp","arguments":{"site":"alpha","args":["--path=/tmp","option","get","home"]}}}' \
    '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"wp_read","arguments":{"site":"alpha","args":["option","update","blogname","x"]}}}' \
    '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"check_page","arguments":{"site":"alpha","body":"none"}}}' \
    | timeout 180 cove mcp)
echo "$out" | grep -q '"serverInfo"' && echo "$out" | grep -q 'https://alpha.localhost' && echo "$out" | grep -q 'exit 0' \
    && echo "$out" | grep -q -- '--path is not offered' && echo "$out" | grep -q 'wp_read runs only commands that read' \
    && echo "$out" | grep -q '→ 200 in'
MCPCHECK
        then
            res "$c" mcp PASS
        else
            res "$c" mcp FAIL
        fi

        # Laravel: a new app on SQLite and one on MariaDB, served and migrated,
        # artisan, a one-time login that signs in, and a clone and delete that
        # take the MariaDB database along. Linux's packaged FrankenPHP has
        # shipped without PDO, which Laravel needs; cove add says so.
        if cx "$c" bash -s <<'LARAVELCHECK'
fail() { echo "laravel: $*" >&2; exit 1; }
# A new site's certificate can take a few seconds more than cove add waits.
up() { local c i; for i in 1 2 3 4 5 6; do c=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 60 "https://$1.localhost/up"); [ "$c" = 200 ] && break; sleep 2; done; echo "$c"; }
# Read, not exported: an exported DB_PASSWORD (MariaDB's) would override
# every app's .env, as Laravel lets the environment win.
. /root/Cove/config
dbs() { MYSQL_PWD="$DB_PASSWORD" mariadb -u "$DB_USER" -N -e 'SHOW DATABASES' 2>/dev/null; }
cove add lvl laravel >/tmp/lv-add.log 2>&1 || fail "cove add (sqlite): $(tail -n 6 /tmp/lv-add.log)"
[ "$(up lvl)" = 200 ] || fail "/up on the SQLite app answered $(up lvl)"
# Added well before it is asked for: PHP rereads a changed file only every
# couple of seconds (opcache.revalidate_freq).
printf '%s\n' "Route::get('/me', fn () => auth()->user()?->email ?? 'guest')->middleware('web');" >> /root/Cove/Sites/lvl.localhost/routes/web.php
cove artisan lvl migrate:status 2>&1 | grep -q 'create_users_table.*Ran' || fail "migrate:status"
cove artisan lvl test >/tmp/lv-test.log 2>&1 || fail "artisan test: $(tail -n 4 /tmp/lv-test.log)"
cove laravel lvl user add m@matrix.test >/tmp/lv-user.log 2>&1 || fail "cove laravel user add: $(tail -n 3 /tmp/lv-user.log)"
cove laravel lvl users | grep -q 'm@matrix.test' || fail "cove laravel users does not list m@matrix.test"
link=$(cove login lvl --plain) || fail "cove login"
code=$(curl -sk --max-time 60 -c /tmp/lv-jar -b /tmp/lv-jar "$link" -o /dev/null -w '%{http_code}')
[ "$code" = 302 ] || fail "the login link answered $code"
me=""
for i in 1 2 3 4 5; do me=$(curl -sk --max-time 60 -b /tmp/lv-jar https://lvl.localhost/me); [ "$me" = m@matrix.test ] && break; sleep 1; done
[ "$me" = m@matrix.test ] || fail "the login link did not sign in: /me said $(echo "$me" | head -c 80)"
# An existing project from a folder outside Cove: copied without vendor/,
# packages installed again, its SQLite rows along with it.
rm -rf /root/lv-src && cp -a /root/Cove/Sites/lvl.localhost /root/lv-src && rm -rf /root/lv-src/logs
cove add lvf --from=/root/lv-src >/tmp/lv-from.log 2>&1 || fail "cove add --from: $(tail -n 8 /tmp/lv-from.log)"
[ "$(up lvf)" = 200 ] || fail "/up on the app from a folder answered $(up lvf)"
cove laravel lvf users | grep -q 'm@matrix.test' || fail "the copied app lost its users"
grep -q "^DB_DATABASE=/root/lv-src" /root/Cove/Sites/lvf.localhost/.env && fail "the copy's .env still names the original's database"
cove delete lvf --force >/dev/null 2>&1 || fail "delete lvf"
# PostgreSQL, set up by the first site that asks for it; its database copied
# by a clone and dropped by a delete.
cove add lvp laravel --database=pgsql >/tmp/lv-addp.log 2>&1 || fail "cove add (pgsql): $(grep -v '^[[:space:]]*$' /tmp/lv-addp.log | tail -n 20)"
[ "$(up lvp)" = 200 ] || fail "/up on the PostgreSQL app answered $(up lvp)"
cove laravel lvp user add p@matrix.test >/dev/null 2>&1 || fail "user add on PostgreSQL"
cove clone lvp lvp2 >/tmp/lv-clonep.log 2>&1 || fail "clone (pgsql): $(tail -n 4 /tmp/lv-clonep.log)"
cove laravel lvp2 users | grep -q 'p@matrix.test' || fail "the PostgreSQL clone lost its users"
cove delete lvp2 --force >/dev/null 2>&1 && cove delete lvp --force >/dev/null 2>&1 || fail "delete (pgsql)"
[ "$(cove postgres psql postgres -tAc "SELECT count(*) FROM pg_database WHERE datname LIKE 'cove_lvp%'")" = 0 ] || fail "delete left a PostgreSQL database"
# Redis, and phpredis in FrankenPHP's PHP: a cache entry under the site's own prefix.
cove redis install >/tmp/lv-redis.log 2>&1 || fail "cove redis install: $(tail -n 4 /tmp/lv-redis.log)"
[ "$(cove redis cli ping)" = PONG ] || fail "Redis doesn't answer PING"
[ "$(cove artisan lvl tinker --execute="config(['cache.default' => 'redis']); Cache::put('matrix', 'ok', 60); echo Cache::get('matrix');" 2>&1 | tail -n 1)" = ok ] || fail "Laravel's cache on Redis"
cove redis cli -n 1 --scan --pattern 'cove:lvl:*' | grep -q . || fail "the cache key isn't under the site's prefix"
# Reverb: added to the app (no Node here, so no Echo), then its websocket
# answered through Caddy at wss://lvl.localhost.
cove laravel lvl reverb install >/tmp/lv-reverb.log 2>&1 || fail "reverb install: $(tail -n 6 /tmp/lv-reverb.log)"
key=$(grep '^REVERB_APP_KEY=' /root/Cove/Sites/lvl.localhost/.env | cut -d= -f2)
code=""
for i in 1 2 3 4 5; do code=$(curl -sk --http1.1 -o /dev/null -w '%{http_code}' -m 5 -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' "https://lvl.localhost/app/$key?protocol=7&client=js&version=8.4.0"); [ "$code" = 101 ] && break; sleep 2; done
[ "$code" = 101 ] || fail "Reverb's websocket through Caddy answered $code"
cove laravel lvl reverb off >/dev/null 2>&1
cove add lvm laravel --database=mysql >/tmp/lv-addm.log 2>&1 || fail "cove add (mysql): $(tail -n 6 /tmp/lv-addm.log)"
[ "$(up lvm)" = 200 ] || fail "/up on the MariaDB app answered $(up lvm)"
if cove login lvm --plain >/dev/null 2>&1; then fail "cove login made a link for an app with no users"; fi
cove clone lvm lvm2 >/tmp/lv-clone.log 2>&1 || fail "clone: $(tail -n 4 /tmp/lv-clone.log)"
[ "$(up lvm2)" = 200 ] || fail "/up on the clone answered $(up lvm2)"
grep -q '^DB_DATABASE=cove_lvm2$' /root/Cove/Sites/lvm2.localhost/.env || fail "the clone's .env names $(grep ^DB_DATABASE= /root/Cove/Sites/lvm2.localhost/.env)"
dbs | grep -qx cove_lvm2 || fail "no cove_lvm2 database"
cove delete lvm2 --force >/dev/null 2>&1 || fail "delete"
if dbs | grep -qx cove_lvm2; then fail "delete left cove_lvm2"; fi
exit 0
LARAVELCHECK
        then
            res "$c" laravel PASS
        else
            res "$c" laravel FAIL
        fi

        # `cove log rotate`: Cove's own logs rotate when asked (by the command
        # and by a real watchdog tick), the services cap trims FrankenPHP's
        # output, and the access-log settings land in a Caddyfile that loads.
        if cx "$c" bash -s <<'LOGROTATE'
fail() { echo "logrotate: $*" >&2; exit 1; }
L=/root/Cove/Logs; CF=/root/Cove/Caddyfile
size() { stat -c%s "$1" 2>/dev/null || echo 0; }
up() { [ "$(curl -sk -o /dev/null -w '%{http_code}' --max-time 20 https://alpha.localhost/)" = 200 ] || fail "alpha not answering after $1"; }
waitfor() { local i; for i in $(seq 1 24); do eval "$1" && return 0; sleep 5; done; return 1; }
cove log rotate | grep -q "Cove's own logs" || fail "status"
head -c 2000000 /dev/urandom | base64 > "$L/errors.log"
cove log rotate 1 >/dev/null || fail "cove log rotate 1"
[ -s "$L/errors.log.1" ] || fail "no errors.log.1 after cove log rotate 1"
[ "$(size "$L/errors.log")" -lt 1048576 ] || fail "errors.log not emptied"
rm -f /root/Cove/.logrotate.stamp "$L/errors.log.1"
head -c 2000000 /dev/urandom | base64 >> "$L/errors.log"
waitfor '[ -s "$L/errors.log.1" ]' || fail "the watchdog did not rotate errors.log"
cove log rotate off >/dev/null || fail "cove log rotate off"
cove log rotate services 1 >/dev/null || fail "services 1"
head -c 2000000 /dev/urandom | base64 >> "$L/caddy-process.log"
waitfor '[ "$(size "$L/caddy-process.log")" -lt 1048576 ]' || fail "the watchdog did not trim caddy-process.log"
cove log rotate services default >/dev/null || fail "services default"
cove log rotate access 5 --keep=2 --days=3 >/dev/null || fail "access 5"
grep -q 'roll_size 5MiB' "$CF" || fail "no roll_size"
grep -q 'roll_keep 2' "$CF" || fail "no roll_keep"
grep -q 'roll_keep_for 72h' "$CF" || fail "no roll_keep_for"
up "access 5"
cove log rotate access off >/dev/null || fail "access off"
grep -q roll_disabled "$CF" || fail "no roll_disabled"
up "access off"
cove log rotate access default >/dev/null || fail "access default"
if grep -q 'roll_' "$CF"; then fail "roll settings left after access default"; fi
up "access default"
exit 0
LOGROTATE
        then
            res "$c" logrotate PASS
        else
            res "$c" logrotate FAIL
        fi

        incus restart "$c"; sleep 25
        if site_has "$c" alpha "Welcome to alpha"; then
            res "$c" reboot PASS
        else
            res "$c" reboot FAIL
        fi

        # `cove uninstall`, last as it takes Cove away (lanes B and C restore
        # their own snapshot): half the distros keep ~/Cove, half --purge it.
        local um=keep
        case "$c" in *2204|*debian13|*rocky9) um=purge ;; esac
        if cx "$c" env UM="$um" bash -s <<'UNINSTALL'
fail() { echo "uninstall ($UM): $*" >&2; exit 1; }
export PATH="/usr/local/bin:$PATH"
if [ "$UM" = purge ]; then
    cove uninstall --purge --yes || fail "cove uninstall --purge exited $?"
else
    cove uninstall --yes || fail "cove uninstall exited $?"
fi
hash -r
command -v cove >/dev/null && fail "cove still on PATH"
for u in cove.service cove-watchdog.timer cove-watchdog.service mailpit.service; do
    [ -e "/etc/systemd/system/$u" ] && fail "$u left"
done
systemctl is-active --quiet cove.service && fail "cove.service still running"
grep -qE '^127\.0\.0\.1[[:space:]]+cove\.localhost' /etc/hosts && fail "/etc/hosts line left"
curl -sk -o /dev/null --max-time 5 https://alpha.localhost/ && fail "alpha still answering"
if [ "$UM" = purge ]; then
    [ -d /root/Cove ] && fail "~/Cove left"
else
    [ -d /root/Cove/Sites/alpha.localhost/public ] || fail "alpha's files gone"
fi
exit 0
UNINSTALL
        then
            res "$c" uninstall PASS
        else
            res "$c" uninstall FAIL
        fi
    } >> "$L" 2>&1
}

lane_b() { # previous release -> candidate + post-upgrade
    local c=$1 L="$D/$c-upgrade.log"
    {
        restore "$c"
        incus file push "$SRC/install-cove.sh" "$c/root/install-cove.sh"
        # Install the PREVIOUS (latest published) release via the fixed installer
        if ! cx "$c" bash -c 'curl -fsSL https://github.com/anchorhost/cove/releases/latest/download/cove.sh -o /root/cove.sh' \
            || ! cx "$c" bash /root/install-cove.sh --dev; then
            res "$c" upgrade_prev FAIL
            res "$c" upgrade_post SKIP
            res "$c" upgrade_site SKIP
            return
        fi
        # A release that can't make a site still gets upgraded: that user is
        # exactly who the candidate has to rescue (v2.2 on FrankenPHP 1.13.0,
        # whose php-cli broke WP-CLI). The candidate then makes the site.
        local prev_made_site=true
        if cx "$c" cove add u1 && site_has "$c" u1 "Welcome to u1"; then
            res "$c" upgrade_prev PASS
        else
            res "$c" upgrade_prev FAIL
            prev_made_site=false
        fi
        # Drop the candidate in place and run its post-upgrade hook —
        # the same sequence cove upgrade performs after downloading.
        incus file push "$SRC/cove.sh" "$c/usr/local/bin/cove"
        # post-upgrade also points cove.service and the watchdog at root's real
        # home (/root): units before 2.4 said /home/root. And it installs PDO,
        # which installs before Laravel support lack, for the web server too.
        if cx "$c" chmod +x /usr/local/bin/cove && cx "$c" cove post-upgrade \
            && cx "$c" systemctl show cove.service -p Environment | grep -q 'HOME=/root' \
            && cx "$c" systemctl show cove-watchdog.service -p Environment | grep -q 'HOME=/root' \
            && cx "$c" bash -c 'PHPRC=/root/Cove/php.ini frankenphp php-cli -r "exit(extension_loaded(\"pdo_sqlite\") && extension_loaded(\"pdo_mysql\") ? 0 : 1);"' \
            && cx "$c" bash -c 'printf "%s" "<?php echo extension_loaded(\"pdo_sqlite\") ? \"pdo-on\" : \"pdo-off\";" > /root/Cove/Sites/u1.localhost/public/pdo-check.php; curl -sk --max-time 20 https://u1.localhost/pdo-check.php | grep -q pdo-on'; then
            res "$c" upgrade_post PASS
        else
            res "$c" upgrade_post FAIL
        fi
        $prev_made_site || cx "$c" cove add u1
        if site_has "$c" u1 "Welcome to u1"; then
            res "$c" upgrade_site PASS
        else
            res "$c" upgrade_site FAIL
        fi
    } >> "$L" 2>&1
}

lane_c() { # non-root user + sudo — the path most real Linux users hit
    local c=$1 L="$D/$c-sudo.log"
    {
        restore "$c"
        cx "$c" bash -c 'command -v sudo >/dev/null || { command -v apt-get >/dev/null && apt-get update -qq && apt-get install -y -qq sudo || dnf install -y -q sudo; }'
        cx "$c" bash -c 'id dev 2>/dev/null || useradd -m -s /bin/bash dev; echo "dev ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/dev'
        incus file push "$SRC/cove.sh" "$c/home/dev/cove.sh"
        incus file push "$SRC/install-cove.sh" "$c/home/dev/install-cove.sh"
        cx "$c" chown -R dev:dev /home/dev
        if cx "$c" su - dev -c 'bash /home/dev/install-cove.sh --dev' && cx "$c" su - dev -c 'cove version' | grep -q "Cove version"; then
            res "$c" sudo_install PASS
        else
            res "$c" sudo_install FAIL
            res "$c" sudo_add SKIP
            res "$c" sudo_upgrade SKIP
            res "$c" sudo_upgrade_prev SKIP
            return
        fi
        if cx "$c" su - dev -c 'cove add usr1' && [ "$(http_code "$c" usr1)" = "200" ]; then
            res "$c" sudo_add PASS
        else
            res "$c" sudo_add FAIL
        fi
        # The follow-ups `sudo cove upgrade` runs, as the user actually runs
        # them. Debian-family sudo resets HOME=/root, which used to make a
        # root-run post-upgrade/reload build /root/Cove and push /root paths
        # into the user's FrankenPHP. Cove must hand control back to the
        # invoking user: no /root/Cove, nothing root-owned under ~/Cove, and
        # the dashboard still serving afterwards.
        if cx "$c" su - dev -c 'sudo cove post-upgrade >/dev/null 2>&1 && sudo cove reload >/dev/null 2>&1' \
            && ! cx "$c" test -d /root/Cove \
            && ! cx "$c" bash -c 'find /home/dev/Cove -maxdepth 3 ! -user dev -print -quit 2>/dev/null | grep -q .' \
            && [ "$(http_code "$c" cove)" = "200" ]; then
            res "$c" sudo_upgrade PASS
        else
            res "$c" sudo_upgrade FAIL
        fi
        # The previous release's own `cove upgrade`, run by this user, to the
        # candidate. With the install dir root's, releases up to 2.4 sudo cp
        # the download over the script they are still running, and bash reads
        # on from their size as an offset into the new file when main returns:
        # the candidate's landing pad has to be there to end it (compile.sh,
        # 5b). The download is the one thing faked: a curl in /usr/local/bin,
        # ahead of the real one on Cove's PATH, hands over the candidate for
        # Cove's release URL and passes everything else to /usr/bin/curl. The
        # previous release's version gets a 0 for its first digit, the same
        # length, so the candidate counts as newer even before its version
        # bump without moving the offset. It passes when the upgrade exits 0
        # without a stray "command not found" or syntax error, and leaves the
        # candidate in place, root's and 755, with no .new beside it.
        if cx "$c" bash -c 'curl -fsSL https://github.com/anchorhost/cove/releases/latest/download/cove.sh -o /root/prev-cove.sh' \
            && cx "$c" bash -s <<'PREV_UPGRADE'
set -e
sed -i 's/^COVE_VERSION="[0-9]/COVE_VERSION="0/' /root/prev-cove.sh
install -m 755 -o root -g root /root/prev-cove.sh /usr/local/bin/cove
install -m 644 /home/dev/cove.sh /usr/local/share/cove-candidate.sh
cat > /usr/local/bin/curl <<'CURL_STUB'
#!/bin/bash
# test-matrix stub: Cove's release download gets the candidate build.
out="" prev="" release=false
for a in "$@"; do
    case "$a" in */anchorhost/cove/releases/*/cove.sh) release=true ;; esac
    [ "$prev" = "-o" ] && out="$a"
    prev="$a"
done
if $release && [ -n "$out" ]; then
    exec cp /usr/local/share/cove-candidate.sh "$out"
fi
exec /usr/bin/curl "$@"
CURL_STUB
chmod 755 /usr/local/bin/curl
PREV_UPGRADE
        then
            local up_rc=0
            cx "$c" su - dev -c 'cove upgrade --yes < /dev/null' > "$D/$c-sudo-upgrade-prev.out" 2>&1 || up_rc=$?
            cat "$D/$c-sudo-upgrade-prev.out"
            cx "$c" rm -f /usr/local/bin/curl
            if [ "$up_rc" = 0 ] \
                && ! grep -qE 'syntax error|: command not found' "$D/$c-sudo-upgrade-prev.out" \
                && cx "$c" cmp -s /usr/local/bin/cove /usr/local/share/cove-candidate.sh \
                && [ "$(cx "$c" stat -c '%U %a' /usr/local/bin/cove)" = "root 755" ] \
                && ! cx "$c" test -e /usr/local/bin/cove.new; then
                res "$c" sudo_upgrade_prev PASS
            else
                echo "sudo_upgrade_prev: cove upgrade exited $up_rc"
                res "$c" sudo_upgrade_prev FAIL
            fi
        else
            cx "$c" rm -f /usr/local/bin/curl
            res "$c" sudo_upgrade_prev FAIL
        fi
    } >> "$L" 2>&1
}

for c in $CONTAINERS; do lane_a "$c" & done
wait
for c in $UPGRADE_LANE; do lane_b "$c" & done
for c in $SUDO_LANE;    do lane_c "$c" & done
wait

# Park the fleet after a fully green run — the containers only exist for
# these tests, so hand the box's RAM/CPU back to its other workloads. Any
# failure leaves everything running so the failed container can be inspected
# (web terminal in the Incus UI, or `incus exec`).
if ! grep -q '|FAIL$' "$D/results.txt"; then
    incus stop -f $CONTAINERS
    echo "PARKED" > "$D/PARKED"
fi
touch "$D/DONE"
RUNNER_EOF

# --- Deploy + launch ---
echo "📦 Deploying candidate build + runner to $BOX..."
scp -q "$SCRIPT_DIR/cove.sh" "$SCRIPT_DIR/install-cove.sh" "$RUNNER" "$BOX:$REMOTE_DIR/"
ssh "$BOX" "mv $REMOTE_DIR/$(basename "$RUNNER") $REMOTE_DIR/matrix-runner.sh && chmod +x $REMOTE_DIR/matrix-runner.sh && rm -rf $REMOTE_DIR/matrix && (setsid nohup $REMOTE_DIR/matrix-runner.sh > $REMOTE_DIR/matrix-runner.out 2>&1 < /dev/null &) && echo '🚀 Matrix launched.'"
rm -f "$RUNNER"

if $ASYNC; then
    echo "Running in background on the box. Check progress with: ./test-matrix.sh report"
    exit 0
fi

echo "⏳ Waiting for the matrix to finish (typically 10–20 min)..."
while ! ssh "$BOX" "test -f $REMOTE_DIR/matrix/DONE" 2>/dev/null; do
    sleep 30
done
render_report
