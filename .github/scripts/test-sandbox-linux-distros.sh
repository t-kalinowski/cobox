#!/usr/bin/env bash
set -euo pipefail

# Exercise portable artifacts with each distribution's own shell and libraries.
# Containers share the host kernel; this does not certify distribution kernels.
artifacts=$(realpath "${1:?usage: test-sandbox-linux-distros.sh ARTIFACT_DIR IMAGE...}")
shift
(( $# > 0 ))
for binary in mcp-console-sandbox bwrap mcp-console-sandbox-fixture; do
  test -x "$artifacts/$binary"
done

for image in "$@"; do
  docker pull "$image"
  docker run --rm -i --network none --user 1000:1000 \
    --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined \
    --mount "type=bind,src=$artifacts,dst=/opt/cobox,readonly" \
    --workdir /tmp "$image" /bin/sh -s <<'SH'
set -eu
cat /etc/os-release
uname -r
mkdir -p /tmp/check/writable /tmp/check/private
printf original > /tmp/check/read-only
printf secret > /tmp/check/secret
cd /tmp/check
export POLICY='{
  "filesystem":{"kind":"restricted","entries":[
    {"path":{"type":"special","value":{"kind":"root"}},"access":"read"},
    {"path":{"type":"path","path":"/tmp/check/writable"},"access":"write"},
    {"path":{"type":"path","path":"/tmp/check/secret"},"access":"deny"}
  ]},
  "network":"restricted",
  "inherit_environment":false,
  "environment":{"PATH":"/usr/bin:/bin"},
  "lifecycle":{"private_tmp":{"parent":"/tmp/check/private","environment":["TMPDIR"]}}
}'
run() {
  # Force ordinary bundled-helper discovery, independent of installed bwrap.
  PATH=/no-system-helper /opt/cobox/mcp-console-sandbox --config-env POLICY -- "$@"
}
run /bin/sh -eu -c '
  test "$(cat /tmp/check/read-only)" = original
  printf allowed > /tmp/check/writable/created
  test "$(cat /tmp/check/writable/created)" = allowed
  if cat /tmp/check/secret >/dev/null 2>&1; then exit 1; fi
  if (printf escaped > /tmp/check/read-only) 2>/dev/null; then exit 1; fi
  if (printf escaped > /tmp/check/outside) 2>/dev/null; then exit 1; fi
  printf temporary > "$TMPDIR/data"
'
test "$(cat /tmp/check/read-only)" = original
test "$(cat /tmp/check/secret)" = secret
test ! -e /tmp/check/outside

status=0
run /opt/cobox/mcp-console-sandbox-fixture connect 127.0.0.1:9 2>network-error || status=$?
test "$status" = 1
# An unused port or isolated container alone would report a different error.
grep -F 'Operation not permitted (os error 1)' network-error

status=0
printf x | run /opt/cobox/mcp-console-sandbox-fixture lifecycle normal-tree || status=$?
test "$status" = 42
test -z "$(ls -A /tmp/check/private)"
printf 'filesystem, network, exit status, and descendant retirement passed\n'
SH
done
