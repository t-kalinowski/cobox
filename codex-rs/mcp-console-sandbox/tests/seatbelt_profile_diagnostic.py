"""Compare the failed full policy through sandbox-exec and native sandbox init."""

import ctypes
import errno
import json
import os
import socket
import subprocess
import sys
from pathlib import Path


def connect(port: int) -> dict:
    with socket.socket() as stream:
        try:
            stream.connect(("127.0.0.1", port))
        except OSError as error:
            return {"errno": error.errno, "local": stream.getsockname()}
        return {"errno": None, "local": stream.getsockname()}


if len(sys.argv) > 1:
    mode, *ports = sys.argv[1:]
    if mode in ("init", "exec"):
        profile = sys.stdin.read().encode()
        sandbox = ctypes.CDLL("/usr/lib/libsandbox.dylib")
        sandbox.sandbox_init_with_parameters.argtypes = [
            ctypes.c_char_p,
            ctypes.c_uint64,
            ctypes.POINTER(ctypes.c_char_p),
            ctypes.POINTER(ctypes.c_char_p),
        ]
        error = ctypes.c_char_p()
        result = sandbox.sandbox_init_with_parameters(
            profile, 0, (ctypes.c_char_p * 1)(None), ctypes.byref(error)
        )
        assert result == 0, error.value
        if mode == "exec":
            os.execv(sys.executable, [sys.executable, __file__, "connect", *ports])
    print(json.dumps([connect(int(port)) for port in ports]))
    sys.exit(0)

template = Path(__file__).with_suffix(".sbpl").read_text()
failures = 0
for mode in ("sandbox-exec", "init", "exec"):
    for port in (49243, 49438, 49538):
        for iteration in range(20):
            with (
                socket.socket() as http,
                socket.socket() as socks,
                socket.socket() as denied,
            ):
                http.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                http.bind(("127.0.0.1", port))
                socks.bind(("127.0.0.1", 0))
                denied.bind(("127.0.0.1", 0))
                for listener in (http, socks, denied):
                    listener.listen()
                ports = [
                    str(listener.getsockname()[1]) for listener in (http, socks, denied)
                ]
                profile = template.replace("@HTTP_PORT@", ports[0]).replace(
                    "@SOCKS_PORT@", ports[1]
                )
                command = [sys.executable, __file__, mode, *ports]
                if mode == "sandbox-exec":
                    command = [
                        "/usr/bin/sandbox-exec",
                        "-p",
                        profile,
                        sys.executable,
                        __file__,
                        "connect",
                        *ports,
                    ]
                result = subprocess.run(
                    command,
                    input=profile,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                assert result.returncode == 0, (
                    mode,
                    ports,
                    result.stdout,
                    result.stderr,
                )
                observed = json.loads(result.stdout)
                if [entry["errno"] for entry in observed] != [None, None, errno.EPERM]:
                    print(
                        json.dumps(
                            {
                                "mode": mode,
                                "ports": ports,
                                "iteration": iteration,
                                "observed": observed,
                                "stderr": result.stderr,
                            }
                        ),
                        flush=True,
                    )
                    failures += 1
                    break
        else:
            print(
                f"{mode} port={port}: 20 independent full-profile checks passed",
                flush=True,
            )
sys.exit(bool(failures))
