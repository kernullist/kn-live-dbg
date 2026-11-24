"""Compare saved clock-change windows with Get-WinEvent on an original System export."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import struct
import subprocess
import tempfile


triage = runpy.run_path(str(Path(__file__).with_name("test-crash-diagnosis.py")))["triage"]


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def oracle(path, first, last):
    program = r"""
$ErrorActionPreference = 'Stop'
$begin = [uint64]$env:KN_CLOCK_FIRST
$end = [uint64]$env:KN_CLOCK_LAST
$filter = "*[System[(EventRecordID >= $begin and EventRecordID <= $end)]]"
$rows = @(Get-WinEvent -Path $env:KN_CLOCK_ARCHIVE -FilterXPath $filter -Oldest)
$anchor = @($rows | Where-Object RecordId -eq $end)
if ($anchor.Count -ne 1 -or $anchor[0].ProviderName -cne 'Microsoft-Windows-Kernel-Power' -or $anchor[0].Id -ne 41) {
    throw 'Supply a Kernel-Power 41 endpoint'
}
$anchor = $anchor[0]
$scoped = @($rows | Where-Object { $_.LogName -ceq 'System' -and $_.MachineName -ceq $anchor.MachineName })
$changes = @($scoped | Where-Object { $_.ProviderName -ceq 'Microsoft-Windows-Kernel-General' -and $_.Id -eq 1 } | ForEach-Object {
    $xml = ([xml]$_.ToXml()).Event
    $old = [Xml.XmlConvert]::ToDateTimeOffset(($xml.EventData.Data | Where-Object Name -ceq OldTime).'#text').ToFileTime()
    $new = [Xml.XmlConvert]::ToDateTimeOffset(($xml.EventData.Data | Where-Object Name -ceq NewTime).'#text').ToFileTime()
    [pscustomobject]@{id=[string]$_.RecordId; version=$_.Version; old=[string]$old; new=[string]$new; delta=[string]($new-$old)}
})
[pscustomobject]@{count=$rows.Count; scoped=$scoped.Count; changes=$changes; time=[string]$anchor.TimeCreated.ToFileTimeUtc();
    stop=@($anchor.Properties[0..4] | ForEach-Object { [string][uint64]$_.Value })} | ConvertTo-Json -Depth 5 -Compress
"""
    env = dict(os.environ, KN_CLOCK_FIRST=str(first), KN_CLOCK_LAST=str(last), KN_CLOCK_ARCHIVE=str(path))
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", program],
                            env=env, capture_output=True, check=True, timeout=60)
    return json.loads(result.stdout)


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def verify(args, work):
    exe, log = args.exe.resolve(), args.archive.resolve()
    first, last = args.first, args.last
    original = digest(log)
    expected = oracle(log, first, last)
    check(expected["count"] == last - first + 1, "supply a contiguous window of saved record IDs")
    check(expected["changes"] and int(expected["changes"][0]["id"]) < last - 1, "a clock change and an intervening record are required")
    dump = work / "controlled.dmp"
    fields = list(map(int, expected["stop"]))
    data = triage(code=fields[0] or 0x124)
    struct.pack_into("<4Q", data, 0x40, *fields[1:])
    struct.pack_into("<q", data, 0xfa8, int(expected["time"]) + 300_000_000)
    struct.pack_into("<q", data, 0x1030, 400_000_000)
    dump.write_bytes(data)
    base = [exe, "--crash-diagnose", dump, "--sha256", digest(dump), "--reboot-log"]
    def command(source, pin, record, start):
        return [*base, source, "--log-sha256", pin, "--record-id", str(record), "--compare-time",
                "--clock-history-from", str(start)]

    def read(source, pin, record, start):
        cmd = command(source, pin, record, start)
        result = subprocess.run(cmd, capture_output=True, check=True, timeout=45)
        report = json.loads(result.stdout)
        history = report["clock_history"]
        hypotheses = report["assessment"]["hypotheses"]
        step = next(h for h in hypotheses if h["candidate"] == "wall_clock_step_in_saved_restart_window")
        check(report["schema"] == "kn.crash_diagnosis.v5" and history["schema"] == "kn.reboot_clock_history.v1", "opt-in schema")
        check(not result.stderr and report["assessment"]["attributed_cause"] is None and
              not history["dump_clock_correspondence_verified"] and not report["reboot_event"]["same_host_boot_verified"], "attribution boundaries")
        for pointer in step["support"] + step["contrary"] + step["missing"]:
            node = report
            for key in pointer[1:].split("/"):
                node = node[key]
        return report, history, step

    def compare(history, anticipated):
        check(history["records_read"] == anticipated["count"] and history["same_channel_and_computer_records"] == anticipated["scoped"],
              "record denominators agree with independent reader")
        changes = history["changes"]
        check(len(changes) == len(anticipated["changes"]), "all clock rows present")
        for row, witness in zip(changes, anticipated["changes"]):
            check((row["record_id"], row["version"], row["status"], row["win32_error"]) ==
                  (witness["id"], witness["version"], "observed", None), "change locator and qualification")
            check(row["clock_old_filetime"] == row["clock_typed_old_filetime"] == witness["old"] and
                  row["clock_new_filetime"] == row["clock_typed_new_filetime"] == witness["new"] and
                  row["clock_delta_100ns"] == witness["delta"], "XML, typed and independent UTC values agree")

    report, complete, step = read(log, original, last, first)
    compare(complete, expected)
    single_label = expected["scoped"] == expected["count"]
    check(complete["status"] == ("saved_window_observed" if single_label else "partial_saved_window") and
          complete["saved_window_complete"] == single_label, "every requested ID must also match the endpoint scope")
    check(complete["requested_record_ids"] == last - first + 1 and complete["first_record_id"] == str(first) and
          complete["last_record_id"] == str(last), "inclusive record ID boundaries")
    signs = {int(row["delta"]) > 0 for row in expected["changes"] if int(row["delta"])}
    state = ("forward_and_backward_steps_observed" if len(signs) == 2 else "forward_step_observed" if True in signs
             else "backward_step_observed" if False in signs else "no_step_in_saved_window" if single_label else "unresolved")
    check(step["state"] == state, "direction of steps")
    v4 = json.loads(subprocess.check_output(command(log, original, last, first)[:-2], timeout=45))
    check(v4["schema"] == "kn.crash_diagnosis.v4" and report["reboot_timeline"] == v4["reboot_timeline"] and
          report["reboot_event"] == v4["reboot_event"], "original clock comparison preserved")
    if fields[0]:
        check(report["reboot_event"]["same_stop_tuple"] and report["reboot_timeline"]["status"] == "dump_after_event",
              "stop-field support coexists with contrary recorded order")
    change_id = int(expected["changes"][0]["id"])
    reduced = work / "filtered.evtx"
    select = f"*[System[(EventRecordID = {change_id} or EventRecordID = {last})]]"
    subprocess.run(["wevtutil.exe", "epl", log, reduced, "/lf:true", "/q:" + select], check=True, capture_output=True, timeout=30)
    reduced_pin = digest(reduced)
    _, partial, partial_step = read(reduced, reduced_pin, last, first)
    compare(partial, oracle(reduced, first, last))
    check(partial["records_read"] == 2 and not partial["saved_window_complete"] and
          partial["status"] == "partial_saved_window" and "/clock_history/status" in partial_step["missing"], "filtered export keeps holes")
    _, alone, negative = read(reduced, reduced_pin, last, last)
    check(alone["saved_window_complete"] and alone["records_read"] == 1 and not alone["changes"] and
          negative["state"] == "no_step_in_saved_window", "one complete saved ID with no adjustment")
    for record, pin, why in ((last - 1, reduced_pin, "record_not_found"), (change_id, reduced_pin, "different_event_source"),
                             (last, "0" * 64, "event_digest_mismatch")):
        doc, absent, unknown = read(reduced, pin, record, record)
        check(doc["reboot_event"]["status"] == why and not absent["changes"] and not absent["saved_window_complete"] and
              unknown["state"] == "unresolved", "missing, wrong-provider or unpinned anchor")
    missing_doc, missing_history, _ = read(work / "missing.evtx", reduced_pin, last, first)
    check(missing_doc["reboot_event"]["win32_error"] in (2, 3) and not missing_history["records_read"], "original open error")
    with reduced.open("ab"):
        busy, busy_history, _ = read(reduced, reduced_pin, last, first)
    check(busy["reboot_event"]["win32_error"] == 32 and not busy_history["changes"], "active writer keeps its sharing error")
    for start in (0, last + 1, "18446744073709551616", "-1", "+1", "1.0"):
        bad = subprocess.run(command(log, original, last, start), capture_output=True, timeout=10)
        check(bad.returncode == 2 and not bad.stdout and b"--clock-history-from" in bad.stderr, "invalid record range")
    invalid = command(log, original, 8193, 1)
    check(subprocess.run(invalid, capture_output=True, timeout=10).returncode == 2, "8193 IDs exceed admission")
    if last >= 8192:
        _, maximum, _ = read(reduced, reduced_pin, last, last - 8191)
        check(maximum["requested_record_ids"] == 8192 and maximum["records_read"] == 2 and
              not maximum["saved_window_complete"], "maximum admitted window preserves missing IDs")
    _, top, _ = read(reduced, reduced_pin, 2**64 - 1, 2**64 - 2)
    check(top["requested_record_ids"] == 2 and not top["changes"] and not top["saved_window_complete"], "full-width ID bounds")
    alias = work / "alias"
    os.link(reduced, alias)
    with alias.open("ab") as sink:
        blocked = subprocess.run(command(reduced, reduced_pin, last, first), stdout=sink, stderr=subprocess.PIPE, timeout=10)
    check(blocked.returncode == 2 and not blocked.stderr and digest(reduced) == reduced_pin, "redirected source alias")
    with alias.open("ab") as sink:
        blocked = subprocess.run(command(reduced, reduced_pin, last, 0), stdout=subprocess.PIPE, stderr=sink, timeout=10)
    check(blocked.returncode == 2 and not blocked.stdout and digest(reduced) == reduced_pin, "usage output alias")
    check(digest(log) == original, "original saved log preserved")
    print(f"Verified {expected['count']} contiguous records, {expected['scoped']} in scope, clock-change rows={len(expected['changes'])}, a two-record filtered export, "
          "the unchanged v4 clock comparison and missing, range and alias cases.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--first", type=int, required=True)
    parser.add_argument("--last", type=int, required=True)
    opts = parser.parse_args()
    if not 1 <= opts.first <= opts.last <= 2**64 - 1 or opts.last - opts.first >= 8192:
        parser.error("use an inclusive window of 1 to 8192 positive record IDs")
    with tempfile.TemporaryDirectory(prefix="kn-clock-history-") as temp:
        verify(opts, Path(temp))
