"""Distinguish endpoint matching from per-process socket lifetime on macOS 14."""

import errno
import json
import os
import socket
import subprocess
import sys


def connect(port: int, retained: list[socket.socket] | None) -> dict:
    stream = socket.socket()
    if retained is not None:
        retained.append(stream)
    try:
        try:
            stream.connect(("127.0.0.1", port))
        except OSError as error:
            return {"errno": error.errno, "local": stream.getsockname()}
        return {"errno": None, "local": stream.getsockname()}
    finally:
        if retained is None:
            stream.close()


if len(sys.argv) > 1:
    lifetime, allowed_port, denied_port = sys.argv[1:]
    retained = [] if lifetime == "held" else None
    # Every sample uses a new socket. Keep the original failure even if another
    # socket succeeds; these observations never turn a failed case into a pass.
    samples = [
        [connect(int(allowed_port), retained), connect(int(denied_port), retained)]
        for _ in range(8)
    ]
    for stream in retained or []:
        stream.close()
    print(json.dumps({"pid": os.getpid(), "samples": samples}))
    sys.exit(0)

failures = {lifetime: 0 for lifetime in ("closed", "held")}
for iteration in range(300):
    with socket.socket() as allowed, socket.socket() as denied:
        allowed.bind(("127.0.0.1", 0))
        denied.bind(("127.0.0.1", 0))
        allowed.listen()
        denied.listen()
        port = allowed.getsockname()[1]
        blocked = denied.getsockname()[1]
        assert [connect(port, None)["errno"], connect(blocked, None)["errno"]] == [
            None,
            None,
        ]
        profile = (
            "(version 1)(allow default)(deny network*)"
            f'(allow network-outbound (remote ip "localhost:{port}"))'
        )
        for lifetime in ("closed", "held"):
            result = subprocess.run(
                [
                    "/usr/bin/sandbox-exec",
                    "-p",
                    profile,
                    sys.executable,
                    __file__,
                    lifetime,
                    str(port),
                    str(blocked),
                ],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            assert result.returncode == 0, (result.stdout, result.stderr)
            observed = json.loads(result.stdout)
            if any(
                [entry["errno"] for entry in sample] != [None, errno.EPERM]
                for sample in observed["samples"]
            ):
                failures[lifetime] += 1
                print(
                    json.dumps(
                        {
                            "lifetime": lifetime,
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

print(json.dumps({"independent_cases_per_form": 300, "failures": failures}), flush=True)
sys.exit(any(failures.values()))
