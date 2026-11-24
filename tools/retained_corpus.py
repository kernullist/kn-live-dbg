"""Stream original files for a pinned imported benchmark without opening paths from its declarations."""
import hashlib
import os
import stat
import struct
from collections import Counter
from contextlib import contextmanager
from pathlib import Path

from owned_module_benchmark import check, publish_new, sha
from saved_etl_comparison import local_path, outputs_safe


MAGIC = b"KNCORP1\0"
HEADER = struct.Struct("<8sIII")
OBJECT = struct.Struct("<32sQ")
CHUNK = 1 << 20
MAX_DOCUMENT = 8 << 20
MAX_PACKAGE = 8 << 30
MAX_ORIGINALS = 4 * 4096 + 2


class OutputCollision(ValueError):
    pass


@contextmanager
def regular_file(path):
    path = local_path(path)
    check(stat.S_ISREG(path.stat().st_mode), "expected a regular local input")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        check(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "expected an open regular file")
        if not outputs_safe((), stream):
            raise OutputCollision("an output aliases an original input")
        yield stream


def document_bytes(path):
    with regular_file(path) as source:
        raw = source.read(MAX_DOCUMENT + 1)
    check(0 < len(raw) <= MAX_DOCUMENT, "invalid corpus or results size")
    return raw


def listed_originals(arguments, decode):
    # Resolve the operator's list before argparse can send usage to an aliased output.
    paths = []
    used = False
    for index, arg in enumerate(arguments):
        flag, separator, value = arg.partition("=")
        if not flag.startswith("--f") or not "--file-list".startswith(flag):
            continue
        check(not used, "supply one original file list")
        used = True
        if not separator:
            check(index + 1 < len(arguments) and not arguments[index + 1].startswith("--"), "missing original file list")
            value = arguments[index + 1]
        source = local_path(value)
        record = decode(document_bytes(source))
        check(type(record) is dict and record.keys() == {"schema", "original_files"} and
              record["schema"] == "kn.benchmark_original_files.v1", "invalid original file list")
        entries = record["original_files"]
        check(type(entries) is list and len(entries) <= MAX_ORIGINALS, "invalid original file list")
        for name in entries:
            check(type(name) is str and name and "\0" not in name, "invalid original filename")
            local_path(name)  # Reject device and drive-relative names before joining to the list's parent.
            paths.append(os.fspath(local_path(source.parent / Path(name))))
    return paths


def references(cases, assessments, tool):
    refs = {tool["binary_sha256"], tool["config_sha256"]}
    for case in cases.values():
        refs.update((case["artifact_sha256"], case["holes_sha256"], case["truth_ref_sha256"]))
    refs.update(row["evidence_sha256"] for row in assessments.values())
    refs.discard(None)
    return refs


def copy_exact(source, size, *consumers):
    while size:
        block = source.read(min(CHUNK, size))
        check(block, "truncated original bytes")
        for consume in consumers:
            consume(block)
        size -= len(block)


def seal(destination, corpus, results, originals, allowed):
    check(len(originals) <= MAX_ORIGINALS, "too many original inputs")
    retained = set()

    def write(out):
        out.write(HEADER.pack(MAGIC, len(corpus), len(results), 0))
        out.write(corpus)
        out.write(results)
        consumed = out.tell()
        for path in originals:
            with regular_file(path) as source:
                size = os.fstat(source.fileno()).st_size
                consumed += OBJECT.size + size
                check(consumed <= MAX_PACKAGE, "original inputs exceed the byte budget")
                start = out.tell()
                out.write(OBJECT.pack(bytes(32), size))
                digest = hashlib.sha256()

                copy_exact(source, size, out.write, digest.update)
                check(not source.read(1), "original size changed during retention")
            pin = digest.hexdigest()
            check(pin in allowed, "an original is outside the declared corpus and results")
            out.seek(start)
            if pin in retained:
                out.truncate()
                continue
            retained.add(pin)
            out.write(OBJECT.pack(digest.digest(), size))
            out.seek(size, os.SEEK_CUR)
        out.seek(0)
        out.write(HEADER.pack(MAGIC, len(corpus), len(results), len(retained)))

    pin = publish_new(local_path(destination), write)
    return dict(schema="kn.benchmark_retention.v1", package_sha256=pin, corpus_sha256=sha(corpus),
                results_sha256=sha(results), referenced_objects=len(allowed), retained_objects=len(retained))


def read(stream, package_pin, plan_pin):
    size = os.fstat(stream.fileno()).st_size
    check(HEADER.size <= size <= MAX_PACKAGE, "invalid retained corpus size")
    package = hashlib.sha256()

    def take(n):
        data = stream.read(n)
        check(len(data) == n, "truncated retained corpus")
        package.update(data)
        return data

    magic, csize, rsize, count = HEADER.unpack(take(HEADER.size))
    check(magic == MAGIC and 0 < csize <= MAX_DOCUMENT and 0 < rsize <= MAX_DOCUMENT and count <= MAX_ORIGINALS
          and HEADER.size + csize + rsize + count * OBJECT.size <= size, "invalid retained corpus header")
    corpus = take(csize)
    check(sha(corpus) == plan_pin, "registered corpus SHA-256 mismatch")
    results = take(rsize)
    retained = {}
    for _ in range(count):
        raw_pin, length = OBJECT.unpack(take(OBJECT.size))
        pin = raw_pin.hex()
        check(pin not in retained and length <= size - stream.tell(), "duplicate or truncated retained original")
        start = stream.tell()
        digest = hashlib.sha256()

        copy_exact(stream, length, digest.update, package.update)
        check(digest.digest() == raw_pin, "retained original SHA-256 mismatch")
        retained[pin] = (start, length)
    check(stream.tell() == size and not stream.read(1), "unexpected trailing package bytes")
    check(package.hexdigest() == package_pin, "retained package SHA-256 mismatch")
    return corpus, results, retained


def restore(stream, destination, pin, extent):
    offset, length = extent

    def write(out):
        stream.seek(offset)
        digest = hashlib.sha256()

        copy_exact(stream, length, out.write, digest.update)
        check(digest.hexdigest() == pin, "selected original changed during recovery")

    publish_new(local_path(destination), write)


def evidence(cases, assessments, tool, retained, allowed):
    def status(pin):
        if pin is None:
            return "not_referenced"
        return "verified" if pin in retained else "missing"

    tool_roles = {role: status(tool[role]) for role in ("binary_sha256", "config_sha256")}
    tool_available = all(value == "verified" for value in tool_roles.values())
    scored, rows = {}, []
    coverage = Counter()
    for key, case in cases.items():
        assessment = assessments.get(key)
        roles = {role: status(case[role]) for role in ("artifact_sha256", "holes_sha256", "truth_ref_sha256")}
        roles["evidence_sha256"] = status(assessment["evidence_sha256"] if assessment else None)
        complete = tool_available and "missing" not in roles.values() and roles["evidence_sha256"] == "verified"
        if complete:
            scored[key] = assessment
        for role, value in roles.items():
            coverage[role, value] += 1
        rows.append(dict(case_id=key, declared_outcome=assessment["outcome"] if assessment else "missing",
                         original_status=roles, assessment_with_originals=complete))
    totals = {role: {state: coverage[role, state] for state in ("verified", "missing", "not_referenced")}
              for role in ("artifact_sha256", "holes_sha256", "truth_ref_sha256", "evidence_sha256")}
    return scored, dict(referenced_objects=len(allowed), verified_objects=len(retained), missing_sha256=sorted(allowed - retained),
                        tool_originals=tool_roles,
                        case_originals=totals, cases=rows)
