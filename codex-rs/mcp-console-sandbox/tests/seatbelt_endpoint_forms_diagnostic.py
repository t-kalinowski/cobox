"""Compare IP and TCP endpoint filters on the same held loopback listeners."""

import errno
import json
import socket
import subprocess
import sys

# sys/socket.h; match Rust's TcpStream setup on macOS.
SO_NOSIGPIPE = 0x1022


def connect(port: int) -> dict:
    with socket.socket() as stream:
        stream.setsockopt(socket.SOL_SOCKET, SO_NOSIGPIPE, 1)
        try:
            stream.connect(("127.0.0.1", port))
        except OSError as error:
            return {"errno": error.errno, "local": stream.getsockname()}
        return {"errno": None, "local": stream.getsockname()}


if len(sys.argv) > 1:
    print(json.dumps([connect(int(port)) for port in sys.argv[1:]]))
    sys.exit(0)

failures = {form: 0 for form in ("ip", "tcp")}
for iteration in range(200):
    with socket.socket() as allowed, socket.socket() as denied:
        allowed.bind(("127.0.0.1", 0))
        denied.bind(("127.0.0.1", 0))
        allowed.listen()
        denied.listen()
        port = allowed.getsockname()[1]
        blocked = denied.getsockname()[1]
        # Establish reachability outside Seatbelt before both comparisons.
        assert [connect(port)["errno"], connect(blocked)["errno"]] == [None, None]
        filters = {
            "ip": f'(remote ip "localhost:{port}")',
            "tcp": f'(remote tcp "localhost:{port}")',
        }
        for form, endpoint_filter in filters.items():
            profile = (
                "(version 1)(allow default)(deny network*)"
                f"(allow network-outbound {endpoint_filter})"
            )
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
            if [entry["errno"] for entry in observed] != [None, errno.EPERM]:
                failures[form] += 1
                print(
                    json.dumps(
                        {
                            "form": form,
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

print(json.dumps({"independent_cases_per_form": 200, "failures": failures}), flush=True)
sys.exit(any(failures.values()))
