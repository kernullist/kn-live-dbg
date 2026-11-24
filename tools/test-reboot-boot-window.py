"""Check adjacent OS starts against Get-WinEvent and controlled dump clocks."""
import argparse
import json
import os
from pathlib import Path
import runpy
import struct
import subprocess
import tempfile


clock_tests = runpy.run_path(str(Path(__file__).with_name("test-reboot-clock-history.py")))
check, digest, triage = (clock_tests[key] for key in ("check", "digest", "triage"))
TICKS = 10_000_000


def oracle(source, first, last):
    program = r"""
$ErrorActionPreference = 'Stop'
$first = [uint64]$env:KN_BOOT_FIRST
$last = [uint64]$env:KN_BOOT_LAST
$filter = "*[System[(EventRecordID >= $first and EventRecordID <= $last)]]"
$rows = @(Get-WinEvent -Path $env:KN_BOOT_ARCHIVE -FilterXPath $filter -Oldest)
$anchor = $rows[-1]
if ($anchor.RecordId -ne $last -or $anchor.Id -ne 41 -or $anchor.ProviderName -cne 'Microsoft-Windows-Kernel-Power') {
    throw 'Supply a saved Event 41 endpoint'
}
$scoped = @($rows | Where-Object { $_.LogName -ceq 'System' -and $_.MachineName -ceq $anchor.MachineName })
$starts = @($scoped | Where-Object { $_.Id -eq 12 -and $_.ProviderName -ceq 'Microsoft-Windows-Kernel-General' })
if ($starts.Count -lt 2) { throw 'Supply two OS starts' }
$pair = @($starts[-2], $starts[-1] | ForEach-Object {
    $data = ([xml]$_.ToXml()).Event.EventData.Data | Where-Object Name -ceq 'StartTime'
    $xml = [Xml.XmlConvert]::ToDateTimeOffset($data.'#text').ToFileTime()
    if ($_.Version -ne 0 -or $_.Properties[6].Value.ToFileTimeUtc() -ne $xml) { throw 'Unexpected startup template' }
    [pscustomobject]@{id=[string]$_.RecordId; ticks=[string]$xml}
})
$prior = [uint64]$pair[0].id
$suffix = @($scoped | Where-Object RecordId -ge $prior)
if ($suffix.Count -ne $last - $prior + 1) { throw 'Supply a complete same-label boot suffix' }
$steps = @($suffix | Where-Object { $_.Id -eq 1 -and $_.ProviderName -ceq 'Microsoft-Windows-Kernel-General' } | Where-Object {
    $data = ([xml]$_.ToXml()).Event.EventData.Data
    ($data | Where-Object Name -ceq 'OldTime').'#text' -ne ($data | Where-Object Name -ceq 'NewTime').'#text'
})
if ($steps.Count) { throw 'Supply a boot suffix without recorded clock steps for the placement controls' }
[pscustomobject]@{pair=$pair; starts=$starts.Count; scoped=$scoped.Count; read=$rows.Count;
    time=[string]$anchor.TimeCreated.ToFileTimeUtc(); stop=@($anchor.Properties[0..4] | ForEach-Object {[string][uint64]$_.Value})} |
    ConvertTo-Json -Depth 6 -Compress
"""
    env = dict(os.environ, KN_BOOT_FIRST=str(first), KN_BOOT_LAST=str(last), KN_BOOT_ARCHIVE=str(source))
    process = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", program],
                             env=env, capture_output=True, timeout=90)
    check(process.returncode == 0, "Get-WinEvent could not qualify this input: " + process.stderr.decode(errors="replace")[:350])
    return json.loads(process.stdout)


def verify(args, work):
    exe, source = args.exe.resolve(), args.archive.resolve()
    pin = digest(source)
    raw = oracle(source, args.first, args.last)
    previous, receiving = raw["pair"]
    prev_id, recv_id = int(previous["id"]), int(receiving["id"])
    lower, upper = int(previous["ticks"]), int(receiving["ticks"])
    code, *params = map(int, raw["stop"])
    check(code and upper - lower > 8*TICKS and int(raw["time"]) - upper > 4*TICKS and recv_id > prev_id + 1,
          "a nonzero saved stop and separated marker/event times are needed")
    dump = work / "controlled.dmp"

    def write_dump(when, boot, attributes=0):
        data = triage(code=code, attributes=attributes)
        struct.pack_into("<4Q", data, 0x40, *params)
        struct.pack_into("<q", data, 0xfa8, when)
        struct.pack_into("<q", data, 0x1030, when - boot)
        dump.write_bytes(data)

    def arguments(log, log_pin, first):
        return [exe, "--crash-diagnose", dump, "--sha256", digest(dump), "--reboot-log", log,
                "--log-sha256", log_pin, "--record-id", str(args.last), "--compare-time", "--clock-history-from", str(first)]

    def read(log=source, log_pin=pin, first=args.first):
        result = subprocess.run([*arguments(log, log_pin, first), "--boot-window"], capture_output=True, check=True, timeout=45)
        doc = json.loads(result.stdout)
        window = doc["boot_window"]
        check(doc["schema"] == "kn.crash_diagnosis.v6" and window["schema"] == "kn.reboot_boot_window.v1", "schema")
        check(doc["assessment"]["attributed_cause"] is None and not doc["assessment"]["host_crash_verified"] and
              not window["same_host_boot_verified"] and not doc["reboot_event"]["same_host_boot_verified"], "incident provenance")
        return doc, window, next(h for h in doc["assessment"]["hypotheses"] if h["candidate"] == "same_recorded_stop_at_restart")

    write_dump(upper - 3*TICKS, lower)
    doc, window, hypothesis = read()
    for name, expected in (("previous_start", previous), ("receiving_start", receiving)):
        row = window[name]
        check(row["boot_start_record_id"] == expected["id"] and row["status"] == "observed" and row["version"] == 0 and
              row["boot_start_xml_filetime"] == row["boot_start_typed_filetime"] == expected["ticks"], "independent startup fields")
    check(window["status"] == "boot_window_observed" and window["boot_suffix_complete"] and
          window["dump_position"] == "within_previous_boot_window" and window["previous_start_in_estimated_boot"] is True and
          hypothesis["state"] == "consistent_stop_and_previous_boot_window", "previous boot supports a controlled timestamp and uptime")
    check(doc["clock_history"]["same_channel_and_computer_records"] == raw["scoped"] and
          doc["clock_history"]["records_read"] == raw["read"], "full-window denominator")
    for name in ("previous_clock_changes", "receiving_clock_changes"):
        check(window[name] == {"nonzero_steps": 0, "unresolved_changes": 0}, "no scoped clock adjustments")
    _, minimal, _ = read(first=prev_id)
    check(minimal["boot_suffix_complete"] and minimal["contiguous_from_record_id"] == str(prev_id), "minimal complete boot suffix")

    write_dump(upper - 3*TICKS, upper - 6*TICKS)
    _, discordant, h = read()
    check(discordant["dump_position"] == "within_previous_boot_window" and discordant["previous_start_in_estimated_boot"] is False and
          "/boot_window/dump_position" in h["support"] and "/boot_window/previous_start_in_estimated_boot" in h["contrary"] and
          "/boot_window/previous_start" in h["support"] and "/boot_window/previous_start" in h["contrary"] and
          "/boot_window/receiving_start" in h["support"] and "/reboot_timeline/estimated_dump_boot_filetime" in h["contrary"],
          "wall placement and uptime disagree independently")
    write_dump(lower - 2*TICKS, lower - 10*TICKS)
    _, early, _ = read()
    check(early["dump_position"] == "before_previous_start", "older-than-previous stop")

    write_dump(upper + 3*TICKS, upper)
    conflict, window, hypothesis = read()
    legacy = json.loads(subprocess.check_output(arguments(source, pin, args.first), timeout=45))
    for field in ("header", "dbgeng", "reboot_event", "reboot_timeline", "clock_history"):
        check(conflict[field] == legacy[field], "v5 evidence preserved: " + field)
    check(legacy["schema"] == "kn.crash_diagnosis.v5" and "boot_window" not in legacy and
          conflict["reboot_event"]["same_stop_tuple"] and conflict["reboot_timeline"]["status"] == "dump_before_event",
          "matching tuple recorded before the event write")
    check(window["dump_position"] == "at_or_after_receiving_start" and window["previous_start_in_estimated_boot"] is False and
          hypothesis["state"] == "conflicting_recorded_boot_evidence" and "/header/bugcheck" in hypothesis["support"] and
          "/boot_window/dump_position" in hypothesis["contrary"] and "/boot_window/previous_start_in_estimated_boot" in hypothesis["contrary"],
          "receiving boot contradicts the proposed previous incident")

    reduced = work / "gap.evtx"
    gap = prev_id + 1
    query = f"*[System[(EventRecordID >= {prev_id} and EventRecordID <= {args.last}) and (EventRecordID < {gap} or EventRecordID > {gap})]]"
    subprocess.run(["wevtutil.exe", "epl", source, reduced, "/lf:true", "/q:" + query], capture_output=True, check=True, timeout=45)
    reduced_pin = digest(reduced)
    _, partial, h = read(reduced, reduced_pin, prev_id)
    check(partial["previous_start"] == window["previous_start"] and partial["receiving_start"] == window["receiving_start"] and
          partial["status"] == "boot_record_coverage_incomplete" and not partial["boot_suffix_complete"] and
          partial["dump_position"] == "unresolved" and h["state"] == "matching_stop_boot_window_unresolved",
          "one missing interior record blocks placement even when both starts survived")
    _, one, _ = read(first=prev_id + 1)
    check(one["status"] == "two_start_records_unavailable" and one["previous_start"] is None and one["receiving_start"] == window["receiving_start"],
          "single start retained without inventing a predecessor")
    if prev_id > 1:
        suffix = work / "suffix.evtx"
        query = f"*[System[(EventRecordID >= {prev_id} and EventRecordID <= {args.last})]]"
        subprocess.run(["wevtutil.exe", "epl", source, suffix, "/lf:true", "/q:" + query], capture_output=True, check=True, timeout=45)
        reported, intact, _ = read(suffix, digest(suffix), prev_id - 1)
        check(not reported["clock_history"]["saved_window_complete"] and intact["boot_suffix_complete"] and
              intact["contiguous_from_record_id"] == str(prev_id) and intact["dump_position"] == "at_or_after_receiving_start",
              "an omitted ID before the older start does not invalidate the observed suffix")
    _, wrong, _ = read(log_pin="0"*64)
    check(wrong["status"] == "history_unavailable" and wrong["receiving_start"] is None, "mismatched EVTX pin")
    alias = work / "alias"
    os.link(reduced, alias)
    for trailing in (["--boot-window"], ["--boot-window", "--boot-window"]):
        with alias.open("ab") as sink:
            outputs = dict(stdout=sink, stderr=subprocess.PIPE) if len(trailing) == 1 else dict(stdout=subprocess.PIPE, stderr=sink)
            trial = subprocess.run([*arguments(reduced, reduced_pin, prev_id), *trailing], **outputs, timeout=10)
        check(trial.returncode == 2 and digest(reduced) == reduced_pin, "redirected evidence protected")
    bad = subprocess.run([*arguments(source, pin, prev_id)[:-2], "--boot-window"], capture_output=True, timeout=10)
    check(bad.returncode == 2 and not bad.stdout and b"--clock-history-from" in bad.stderr, "boot window requires an explicit history")
    write_dump(upper - 3*TICKS, lower, attributes=0x10)
    _, live, _ = read()
    check(live["boot_suffix_complete"] and live["dump_position"] == "unresolved" and live["previous_start_in_estimated_boot"] is None,
          "live dump cannot qualify an incident clock")
    check(digest(source) == pin, "original EVTX preserved")
    print(f"Verified {raw['starts']} saved starts, {args.last-prev_id+1} records in the adjacent boot suffix, "
          "previous and receiving boot controls, a one-record gap, a single start and unqualified inputs.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", required=True, type=Path)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--first", required=True, type=int)
    parser.add_argument("--last", required=True, type=int)
    args = parser.parse_args()
    if not 1 <= args.first <= args.last < 2**64 or args.last - args.first >= 8192:
        parser.error("use an inclusive window of 1 to 8192 positive record IDs")
    with tempfile.TemporaryDirectory(prefix="kn-boot-window-") as tmp:
        verify(args, Path(tmp))
