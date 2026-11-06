"""Independent content identity checks after path replacement and source removal."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", required=True)
    args = parser.parse_args()
    executable = Path(args.exe).resolve()
    directory = executable.parent / ("run-" + uuid.uuid4().hex)
    run = subprocess.run([str(executable), str(directory)], capture_output=True, text=True, encoding="utf-8", timeout=60)
    print(run.stderr, end="")
    assert run.returncode == 0, "reference blob controls failed"
    result = json.loads(run.stdout)
    assert result["original_sha256"] == hashlib.sha256(b"Q" * 512).hexdigest()
    assert result["replacement_sha256"] == hashlib.sha256(b"B" * 512).hexdigest()
    assert result["original_sha256"] != result["replacement_sha256"]
    assert result["retained_bytes"] == 512 and result["retained_byte"] == ord("Q")
    assert not directory.exists(), "fixture directory survived"
    print("Reference blob JSON oracle passed: exact object, independent SHA-256, cleanup")


if __name__ == "__main__":
    main()
