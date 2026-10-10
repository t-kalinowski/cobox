import json
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from python.runfiles import runfiles


class WrapperArgsTest(unittest.TestCase):
    def test_wrapper_response_file_preserves_substitutions_and_child_arguments(
        self,
    ) -> None:
        wrapper = runfiles.Create().Rlocation(sys.argv.pop())
        with TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            environment = root / "environment"
            environment.write_text(
                "WRAPPER_TEST_VALUE=${TEST_TOKEN}\n", encoding="utf-8"
            )
            flags = root / "wrapper flags"
            substitutions = [
                item
                for index in range(500)
                for item in ("--subst", f"unused_{index}={'x' * 100}")
            ]
            flags.write_text(
                "\n".join(
                    [
                        *substitutions,
                        "--subst",
                        "TEST_TOKEN=expanded value",
                        "--env-file",
                        str(environment),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            child = root / "child.py"
            child_response = root / "child response"
            child_response.write_text("${TEST_TOKEN}\n", encoding="utf-8")
            child.write_text(
                "import json, os, sys\nfrom pathlib import Path\n"
                "print(json.dumps([os.environ['WRAPPER_TEST_VALUE'], sys.argv[1:], "
                "Path(sys.argv[2][1:]).read_text()]))\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    wrapper,
                    f"@{flags}",
                    "--",
                    sys.executable,
                    str(child),
                    "--",
                    f"@{child_response}",
                    "${TEST_TOKEN}",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                json.loads(result.stdout),
                [
                    "expanded value",
                    ["--", f"@{child_response}.expanded", "expanded value"],
                    "expanded value\n",
                ],
            )


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
