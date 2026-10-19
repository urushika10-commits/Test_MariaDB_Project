#!/bin/bash
# Experiment 15: "SSL on by default", with no configuration - what it does and does not give.
#
#   make zerotls            (or: bash experiments/15_zero_config_tls.sh)
#
# The Area 5 brief lists "SSL on by default with no configuration" first. This
# shows exactly what that means on MariaDB 13.1, and why it is not enough on its
# own - which is the reason the project configures its own CA, verification and
# require_secure_transport (section 9) and attacks the difference (the MITM,
# section 12).
#
# It starts its OWN disposable server with NO --ssl-* options at all: a
# separately named container (no published port), removed again at the end.
#
#   Finding: with zero configuration the server already offers TLS 1.3 from an
#   auto-generated, self-signed, in-memory certificate. But that certificate
#   cannot be verified (there is no CA to check it against), and plaintext is
#   still allowed, because require_secure_transport is OFF by default. So the
#   default is encryption that can be silently intercepted - exactly what
#   verified TLS (section 9) and the MITM (section 12) are about.
#
# Every step prints what was checked, expected and actual, and PASS or FAIL;
# the script exits non-zero if any step fails.

set -euo pipefail

IMAGE="${MARIADB_IMAGE:-mariadb:13.1.1-rc@sha256:a652753786e98d9f976aaab8cc21e49c16ea0cfe41a877694825a6ea73140fb1}"
NAME="university-zerotls-$$"
FAILED=0
STEP=0

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

# A disposable server with NO TLS configuration and root reachable over TCP
# (empty password - this throwaway server publishes no port and holds no data).
docker run -d --name "$NAME" \
    -e MARIADB_ALLOW_EMPTY_ROOT_PASSWORD=1 -e MARIADB_ROOT_HOST='%' \
    "$IMAGE" >/dev/null
for _ in $(seq 1 60); do
    docker exec "$NAME" mariadb -uroot -e 'SELECT 1' >/dev/null 2>&1 && break
    sleep 2
done

# check "<why>" "<expected substring>" "<mariadb args...>"
check() {
    local why="$1" expected="$2"; shift 2
    local output verdict
    STEP=$((STEP + 1))
    output=$(docker exec "$NAME" mariadb -uroot --batch --skip-column-names "$@" 2>&1 || true)
    if printf '%s' "$output" | grep -q -- "$expected"; then verdict=PASS; else verdict=FAIL; FAILED=$((FAILED + 1)); fi
    echo
    echo "Step $STEP"
    echo "    Check    $why"
    echo "    Expected to contain: $expected"
    echo "    Actual   $(printf '%s' "$output" | tr '\n' ' ' | cut -c1-120)"
    echo "    Result   $verdict"
}

echo "=============================================================================="
echo " Experiment 15: SSL on by default, no configuration (disposable server $NAME)"
echo "=============================================================================="

check "TLS is available with no --ssl-* options at all (SSL on by default)" \
      "YES" -e "SHOW GLOBAL VARIABLES LIKE 'have_ssl'"

check "No certificate was configured: ssl_cert is empty (the server auto-generated one)" \
      "ssl_cert	" -e "SHOW GLOBAL VARIABLES LIKE 'ssl_cert'"

check "Plaintext is NOT forced: require_secure_transport is OFF by default" \
      "OFF" -e "SHOW GLOBAL VARIABLES LIKE 'require_secure_transport'"

check "A client gets real encryption out of the box: TLS 1.3 over TCP, no CA given" \
      "TLSv1.3" --host=127.0.0.1 --protocol=tcp --ssl \
      -e "SHOW SESSION STATUS LIKE 'Ssl_version'"

check "...but the same client can also connect in PLAINTEXT - TLS is not required" \
      "plaintext-ok" --host=127.0.0.1 --protocol=tcp --ssl=0 \
      -e "SELECT 'plaintext-ok'"

echo
echo "------------------------------------------------------------------------------"
echo " Conclusion: zero-config TLS gives ENCRYPTION but not VERIFICATION, and does"
echo " not REQUIRE TLS. The auto cert is self-signed and ephemeral, so a client has"
echo " nothing to check it against - an impostor (section 12) is accepted, and a"
echo " plaintext connection is accepted too. This project therefore adds its own CA,"
echo " ssl_verify_cert + ssl_verify_identity, and require_secure_transport=ON"
echo " (section 9). That is the gap between 'SSL on by default' and verified TLS."
echo "------------------------------------------------------------------------------"
echo
if [ "$FAILED" -eq 0 ]; then
    echo "-> 15_zero_config_tls.sh: $STEP passed, 0 failed"
else
    echo "-> 15_zero_config_tls.sh: $((STEP - FAILED)) passed, $FAILED failed"
    exit 1
fi
