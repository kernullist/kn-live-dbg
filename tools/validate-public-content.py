"""Offline publication checks. Reports locations/rule names, never matched values.

Default: current tracked and non-ignored untracked files, including new docs.
--index: exact Git index blobs. --tree: every file in a prepared package directory.
Pattern checks cannot prove that arbitrary prose, captures or media contain no secrets.
"""
from __future__ import annotations

import argparse
import json
import re
import stat
import subprocess
from pathlib import Path

PRIVATE_EXTENSIONS = {".pfx", ".p12", ".pem", ".key", ".dmp", ".dump", ".log", ".kncase", ".knledger", ".knindex", ".knchunk", ".knschema", ".knblob", ".knverify"}
PRIVATE_NAMES = {"auth.json", "credentials.json", "mcp-endpoint.json", "id_rsa", "id_ed25519"}
PRIVATE_DIRECTORIES = {".git", ".build", ".vs", ".codex", ".kn-live-dbg",
                       "logs", "knlivedbg-logs", "dump-bin", "symbols", "mcp-clients"}
RULES = {
    "private-key": re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
    "provider-token": re.compile(
        r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|"
        r"sk-(?:proj-|ant-[\w-]*|or-v1-)?[A-Za-z0-9_-]{24,}|"
        r"xox[baprs]-[A-Za-z0-9-]{20,}|AKIA[0-9A-Z]{16}|"
        r"AIza[0-9A-Za-z_-]{35}|glpat-[A-Za-z0-9_-]{20,})\b"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}"),
    "credential-url": re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s/<>\"':]+:[^\s/<>\"'@]+@"),
    "signed-url": re.compile(r"[?&](?:access_token|api_key|apikey|token|secret|sig|signature|password)=[^\s&<>\"']{8,}", re.I),
    "storage-key": re.compile(r"AccountKey=[A-Za-z0-9+/]{30,}={0,2}"),
}
ENV_SECRET = re.compile(
    r"(?m)^[ \t]*(?:export[ \t]+)?(?:[A-Z][A-Z0-9]*_)*(?:API_KEY|ACCESS_TOKEN|AUTH_TOKEN|CLIENT_SECRET|PASSWORD|SECRET_ACCESS_KEY)[ \t]*=[ \t]*(\S[^\r\n]*)")
PROFILE_PATH = re.compile(
    r"(?<![\w/\\])(?:[a-z]:[\\/]+Users[\\/]+|/Users/|/home/)(\w[^\\/\s<>\"`]*)", re.I)
RSA_XML = re.compile(r"<RSAKeyValue>\s*(?:<[A-Za-z]+>[A-Za-z0-9+/=\s]+</[A-Za-z]+>\s*)*<D>[A-Za-z0-9+/=\s]+</D>[\s\S]*?</RSAKeyValue>")
# Synthetic users in checked-in self-tests; never add a developer's real account here.
EXAMPLE_USERS = {"a", "test", "user", "public", "default", "o'brien", "o''brien"}
PLACEHOLDERS = {"", "sk-replace-me", "sk-or-replace-me", "<api-key>", "<password>"}


def path_rule(name: str) -> str | None:
    path = Path(name)
    if any(p.lower() in PRIVATE_DIRECTORIES for p in path.parts[:-1]):
        return "local-state-directory"
    base = path.name.lower()
    if (base.startswith(".env") and base != ".env.example") or base in PRIVATE_NAMES:
        return "credential-file"
    if path.suffix.lower() in PRIVATE_EXTENSIONS or any(
        extension + ".pending-" in base for extension in (".kncase", ".knledger", ".knindex", ".knchunk", ".knschema", ".knblob", ".knverify")
    ):
        return "private-container-or-capture"
    return None


def text_views(data: bytes) -> list[str]:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return [data.decode("utf-16", errors="replace")]
    if b"\0" not in data[:8192]:
        return [data.decode("utf-8-sig", errors="replace")]
    # Inspect printable ASCII and UTF-16 strings in binaries without executing them.
    ascii_strings = re.findall(rb"[\x20-\x7e]{8,}", data)
    wide_strings = re.findall(rb"(?:[\x20-\x7e]\x00){8,}", data)
    return [b"\n".join(ascii_strings).decode("ascii"),
            "\n".join(s.decode("utf-16-le") for s in wide_strings)]


def inspect(name: str, data: bytes, allow_private_symbols: bool = False) -> list[dict]:
    findings = []
    reported_name = name
    for pattern in RULES.values():
        reported_name = pattern.sub("[redacted]", reported_name)
    def add(rule: str, line: int | None = None) -> None:
        item = {"path": reported_name, "rule": rule, "line": line}
        if item not in findings:
            findings.append(item)
    if reported_name != name:
        add("sensitive-filename")
    bad_path = path_rule(name)
    if bad_path:
        add(bad_path)
    private_symbols = Path(name).suffix.lower() == ".pdb"
    if private_symbols and not allow_private_symbols:
        add("private-symbol-file")
    binary = b"\0" in data[:8192] and not data.startswith((b"\xff\xfe", b"\xfe\xff"))
    for text in text_views(data):
        # Capture contents remain private even if the extension was changed.
        if text.lstrip().startswith("{"):
            try:
                document = json.loads(text)
                if isinstance(document, dict) and document.get("schema") in {
                    "kmon.bundle.v1", "kmon.evidence.v1", "kmon.evidence_session.v1",
                    "kn.evidence_inventory.v1", "kn.evidence_inventory_chunk.v1", "kn.observation_read.v1", "kn.type_schema.v1",
                    "kn.image_recipe.v1", "kn.image_replay.v1", "kn.image_capture.v1"
                }:
                    add("private-evidence-bundle")
            except (ValueError, RecursionError):
                pass
        for rule, pattern in RULES.items():
            for match in pattern.finditer(text):
                add(rule, None if binary else text.count("\n", 0, match.start()) + 1)
        if RSA_XML.search(text):
            add("private-rsa-xml")
        for match in ENV_SECRET.finditer(text):
            value = match[1].strip().strip("\"'")
            if value not in PLACEHOLDERS:
                add("environment-secret", None if binary else text.count("\n", 0, match.start()) + 1)
        for match in PROFILE_PATH.finditer(text):
            if match[1].lower() not in EXAMPLE_USERS and not (private_symbols and allow_private_symbols):
                add("personal-profile-path", None if binary else text.count("\n", 0, match.start()) + 1)
    return findings


def git(root: Path, *args: str) -> bytes:
    # Do not copy stderr, which may contain private paths or credentials, into a report.
    return subprocess.check_output(["git", "-C", str(root), *args], stderr=subprocess.PIPE)


def is_reparse(file: Path) -> bool:
    return file.is_symlink() or bool(getattr(file.lstat(), "st_file_attributes", 0) &
                                    getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def inputs(root: Path, index: bool, tree: bool):
    if tree:
        for file in sorted(root.rglob("*")):
            if is_reparse(file):
                raise ValueError("reparse point in package input")
            if file.is_file():
                yield file.relative_to(root).as_posix(), file.read_bytes()
    elif index:
        for entry in git(root, "ls-files", "--stage", "-z").split(b"\0"):
            if not entry:
                continue
            metadata, name = entry.split(b"\t", 1)
            mode, oid, stage = metadata.split()
            if stage != b"0" or mode not in (b"100644", b"100755"):
                raise ValueError("unmerged or non-regular index input")
            yield name.decode("utf-8"), git(root, "cat-file", "blob", oid.decode("ascii"))
    else:
        names = git(root, "ls-files", "--cached", "--others", "--exclude-standard", "-z")
        for name in sorted(set(names.decode("utf-8").split("\0")) - {""}):
            file = root / name
            if not file.exists() and not file.is_symlink():
                continue  # tracked deletion in the current working tree
            if any(is_reparse(p) for p in (file, *file.parents) if p != root and root in p.parents) or not file.resolve().is_relative_to(root):
                raise ValueError("reparse point in working-tree input")
            if file.is_file():
                yield name, file.read_bytes()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--index", action="store_true")
    mode.add_argument("--tree", action="store_true")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--allow-private-symbols", action="store_true",
                        help="permit PDB files and their source-path metadata; still check credentials")
    args = parser.parse_args()
    result = {"mode": "tree" if args.tree else "index" if args.index else "working-tree",
              "files": 0, "bytes": 0, "findings": []}
    try:
        if not args.root.is_dir():
            raise ValueError("input root is not a directory")
        for name, data in inputs(args.root.resolve(), args.index, args.tree):
            result["files"] += 1
            result["bytes"] += len(data)
            result["findings"].extend(inspect(name, data, args.allow_private_symbols))
        if args.tree and result["files"] == 0:
            raise ValueError("empty package input")
    except (OSError, ValueError, subprocess.CalledProcessError):
        # Never report success after an unreadable/unsupported input.
        print("Public-content check failed: an input could not be inspected.")
        return 2
    result["passed"] = not result["findings"]
    rendered = json.dumps(result, ensure_ascii=True, indent=2) + "\n"
    if args.report:
        args.report.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
