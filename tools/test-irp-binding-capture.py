"""Independent oracle for the owned DIA/IRP capture; never opens a live target."""
import argparse
import ctypes as c
import hashlib
import json
from pathlib import Path
import struct
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    root = parser.parse_args().root
    raw = (root / "positive.knirp").read_bytes()
    capture = json.loads(raw)
    assert capture["schema"] == "kn.irp_capture.v2"
    assert int(capture["reference_captured_bytes"]) == (root / "fixture.exe").stat().st_size
    assert capture["final_source_contract_same"] and not capture["final_cancelled"]
    assert int(capture["scan_finished_tick_ms"]) >= int(capture["scan_started_tick_ms"])
    assert capture["runtime_qualified"] and capture["readset_complete"]
    assert capture["enumeration_complete"] and capture["reference_content_stable"]
    for flag in ("collector_authenticated", "reference_image_preserved", "pdb_file_preserved",
                 "whole_image_integrity", "referenced_lifetime", "atomic_snapshot", "execution_observed"):
        assert capture[flag] is False, flag
    schemas = []
    for schema in capture["schemas"]:
        payload = schema["payload"]
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
        assert hashlib.sha256(encoded).hexdigest() == schema["package_sha256"]
        for key, filename in (("image_sha256", "fixture.exe"), ("pdb_sha256", "fixture.pdb"),
                              ("provider_sha256", "msdia140.dll")):
            assert payload[key] == hashlib.sha256((root / filename).read_bytes()).hexdigest()
        schemas.append(payload)

    # Independent C layout model. It does not derive offsets from the product's
    # extracted layout, schema resolver, or parser's result.
    class Link(c.Structure):
        _fields_ = [("Flink", c.c_uint64), ("Blink", c.c_uint64)]

    class Cid(c.Structure):
        _fields_ = [("UniqueProcess", c.c_uint64), ("UniqueThread", c.c_uint64)]

    class Thread(c.Structure):
        _fields_ = [("Padding", c.c_uint8 * 40), ("IrpList", Link), ("Cid", Cid), ("CreateTime", c.c_uint64)]

    class Overlay(c.Structure):
        _fields_ = [("CurrentStackLocation", c.c_uint64), ("Thread", c.c_uint64)]

    class Tail(c.Structure):
        _fields_ = [("Overlay", Overlay)]

    class Status(c.Structure):
        _fields_ = [("Status", c.c_int32)]

    class Irp(c.Structure):
        _fields_ = [("Type", c.c_uint16), ("Size", c.c_uint16), ("Padding", c.c_uint8 * 12),
                    ("ThreadListEntry", Link), ("StackCount", c.c_uint8), ("CurrentLocation", c.c_uint8),
                    ("Cancel", c.c_uint8), ("PendingReturned", c.c_uint8), ("IoStatus", Status), ("Tail", Tail)]

    class Stack(c.Structure):
        _fields_ = [("MajorFunction", c.c_uint8), ("MinorFunction", c.c_uint8), ("Control", c.c_uint8),
                    ("Padding", c.c_uint8 * 13), ("CompletionRoutine", c.c_uint64), ("Context", c.c_uint64),
                    ("DeviceObject", c.c_uint64), ("FileObject", c.c_uint64)]

    fields_checked = 0
    for schema, model in zip(schemas, (Thread, Irp, Stack)):
        assert int(schema["type_bytes"]) == c.sizeof(model)
        for field in schema["fields"]:
            offset, current = 0, model
            for name in field["path"]:
                offset += getattr(current, name).offset
                current = dict(current._fields_)[name]
            assert int(field["offset"]) == offset
            assert int(field["storage_bytes"]) == c.sizeof(current)
            assert int(field["bit_width"]) == 0
            fields_checked += 1

    routed = capture["reads"]
    attempts = routed["attempts"]
    receipts = attempts["reads"]
    calls = routed["parser_reads"]
    assert len(calls) == len(receipts) == int(attempts["charged_source_calls"])
    assert int(routed["unrecorded_parser_calls"]) == int(attempts["unrecorded_attempts"]) == 0
    retained = []
    for index, (call, receipt) in enumerate(zip(calls, receipts), 1):
        assert int(call["primary_receipt"]) == int(call["returned_receipt"]) == int(receipt["sequence"]) == index
        assert call["accepted"] and receipt["completed"] and receipt["source_invoked"]
        address, length = int(call["address"]), int(call["length"])
        assert address == int(receipt["address"]) and length == int(receipt["requested_bytes"])
        assert receipt["requested_source_id"] == "owned_irp_fixture:1"
        chunks = receipt["read"]["spans"]
        assert all(chunk["state"] == "complete" for chunk in chunks)
        data = b"".join(bytes.fromhex(chunk["bytes_hex"]) for chunk in chunks)
        assert len(data) == length
        retained.append((address, data))

    def values(address, length):
        return [data for base, data in retained if base == address and len(data) == length]

    request, = capture["requests"]
    thread, irp = int(request["thread"]), int(request["irp"])
    packets = values(irp, c.sizeof(Irp) + c.sizeof(Stack))
    assert len(packets) == 2 and packets[0] == packets[1]
    decoded = Irp.from_buffer_copy(packets[0])
    stack = Stack.from_buffer_copy(packets[0][c.sizeof(Irp):])
    assert decoded.Type == 6 and decoded.Size == len(packets[0])
    assert decoded.StackCount == decoded.CurrentLocation == 1
    assert decoded.Tail.Overlay.Thread == thread and decoded.Tail.Overlay.CurrentStackLocation == irp + c.sizeof(Irp)
    assert stack.CompletionRoutine == int(request["stacks"][0]["completion"])
    assert stack.Control == 0xE0 and stack.MajorFunction == 3
    for offset, expected in ((Thread.Cid.offset, 100), (Thread.Cid.offset + 8, 200),
                             (Thread.CreateTime.offset, int(request["thread_create_time"]))):
        observed = values(thread + offset, 8)
        assert len(observed) == 2 and all(struct.unpack("<Q", value)[0] == expected for value in observed)
    for address, expected in ((thread + Thread.IrpList.offset, irp + Irp.ThreadListEntry.offset),
                              (thread + Thread.IrpList.offset + 8, irp + Irp.ThreadListEntry.offset),
                              (irp + Irp.ThreadListEntry.offset, thread + Thread.IrpList.offset),
                              (irp + Irp.ThreadListEntry.offset + 8, thread + Thread.IrpList.offset)):
        observed = values(address, 8)
        assert observed and all(struct.unpack("<Q", value)[0] == expected for value in observed)
    base = int(capture["image_base"])
    assert (root / f'irp-reference-{schemas[0]["image_sha256"]}.knblob').read_bytes() == (root / "fixture.exe").read_bytes()
    headers = values(base, 64)
    assert len(headers) == 2 and headers[0] == headers[1] and headers[0][:2] == b"MZ"
    pdb = values(base + int(capture["reference_identity"]["pdb_rva"]), 24)
    assert len(pdb) == 2 and pdb[0] == pdb[1] and pdb[0][:4] == b"RSDS"
    assert uuid.UUID(bytes_le=pdb[0][4:20]).hex == schemas[0]["pdb_guid"]
    assert struct.unpack("<I", pdb[0][20:])[0] == int(schemas[0]["pdb_age"])
    assert request["validation_stage"] == "qualified_observation" and request["build_approval"] == "not_established"
    assert request["process_create_time"] is None and not request["referenced_lifetime"]
    print(f"IRP capture oracle passed: {fields_checked} fields, {len(receipts)} original reads, owner/list/stack/RSDS; sha256={hashlib.sha256(raw).hexdigest()}")


if __name__ == "__main__":
    main()
