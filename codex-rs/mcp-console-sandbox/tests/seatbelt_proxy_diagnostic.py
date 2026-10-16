"""Temporary macOS 14 diagnostic; this branch is not a production runner pin."""

import errno
import json
import socket
import subprocess
import sys


def connect(port: int) -> dict:
    with socket.socket() as stream:
        try:
            stream.connect(("127.0.0.1", port))
        except OSError as error:
            return {"errno": error.errno, "local": stream.getsockname()}
        return {"errno": None, "local": stream.getsockname()}


if len(sys.argv) > 1:
    print(json.dumps([connect(int(port)) for port in sys.argv[1:]]))
    sys.exit(0)

failures = 0
for binding in (False, True):
    for iteration in range(100):
        with socket.socket() as allowed, socket.socket() as denied:
            allowed.bind(("127.0.0.1", 0))
            denied.bind(("127.0.0.1", 0))
            allowed.listen()
            denied.listen()
            port = allowed.getsockname()[1]
            blocked = denied.getsockname()[1]
            profile = (
                "(version 1)(allow default)(deny network*)"
                f'(allow network-outbound (remote ip "localhost:{port}"))'
            )
            if binding:
                profile += '(allow network-bind (local ip "*:*"))'
            result = subprocess.run(
                [
                    "/usr/bin/sandbox-exec",
                    "-p",
                    profile,
                    sys.executable,
                    __file__,
                    str(port),
                    str(blocked),
                ],
                capture_output=True,
                text=True,
                timeout=10,
                check=True,
            )
            observed = json.loads(result.stdout)
            if observed[0]["errno"] is not None or observed[1]["errno"] != errno.EPERM:
                print(
                    json.dumps(
                        {
                            "binding": binding,
                            "iteration": iteration,
                            "allowed_port": port,
                            "denied_port": blocked,
                            "observed": observed,
                            "stderr": result.stderr,
                            "profile": profile,
                        }
                    ),
                    flush=True,
                )
                failures += 1
                break
    else:
        print(f"binding={binding}: 100 independent endpoint checks passed", flush=True)
sys.exit(bool(failures))
