"""Compare the WER reader with native properties from retained System and Application logs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def digest(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def oracle(system, application):
    program = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$system = $env:KN_WER_TEST_SYSTEM
$application = $env:KN_WER_TEST_APPLICATION
function MakeRow($e, $tuple, $guid) {
    [pscustomobject]@{id=[string]$e.RecordId; stop=$tuple; guid=$guid; machine=$e.MachineName;
        time=[string]$e.TimeCreated.ToFileTimeUtc()}
}
$sys = @(Get-WinEvent -Path $system -Oldest -MaxEvents 257 -FilterXPath "*[System[Provider[@Name='Microsoft-Windows-WER-SystemErrorReporting'] and EventID=1001]]" | ForEach-Object {
    if ($_.LogName -cne 'System' -or $_.Version -ne 1) { return }
    $m = [regex]::Match($_.Properties[0].Value, '(?i)^\s*0x([0-9a-f]{1,8})\s*\(\s*0x([0-9a-f]{1,16})\s*,\s*0x([0-9a-f]{1,16})\s*,\s*0x([0-9a-f]{1,16})\s*,\s*0x([0-9a-f]{1,16})\s*\)\s*$')
    if (-not $m.Success) { return }
    $tuple = @(1..5 | ForEach-Object { [string][Convert]::ToUInt64($m.Groups[$_].Value,16) })
    MakeRow $_ $tuple ([Guid]::Parse($_.Properties[2].Value).ToString())
})
$restart = @(Get-WinEvent -Path $system -Oldest -MaxEvents 257 -FilterXPath "*[System[Provider[@Name='Microsoft-Windows-Kernel-Power'] and EventID=41]]" | ForEach-Object {
    if ($_.LogName -ceq 'System' -and $_.Version -in (2..10) -and $_.Properties[0].Value) {
        MakeRow $_ @($_.Properties[0..4] | ForEach-Object { [string][uint64]$_.Value }) $null
    }
})
$app = @(Get-WinEvent -Path $application -Oldest -MaxEvents 257 -FilterXPath "*[System[Provider[@Name='Windows Error Reporting'] and EventID=1001] and EventData[Data[@Name='EventName']='BlueScreen']]" | ForEach-Object {
    if ($_.LogName -ceq 'Application' -and $_.Version -eq 0 -and $_.Properties[2].Value -ceq 'BlueScreen') {
        MakeRow $_ @($_.Properties[5..9] | ForEach-Object { [string][Convert]::ToUInt64($_.Value,16) }) ([Guid]::Parse($_.Properties[19].Value).ToString())
    }
})
if ($sys.Count -ge 257 -or $restart.Count -ge 257 -or $app.Count -ge 257) { throw 'Supply bounded test exports' }
$lastApp = (Get-WinEvent -Path $application -MaxEvents 1).RecordId
@{system=$sys; application=$app; restart=$restart; last_app=[string]$lastApp} | ConvertTo-Json -Depth 6 -Compress
"""
    env = dict(os.environ, KN_WER_TEST_SYSTEM=str(system), KN_WER_TEST_APPLICATION=str(application))
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", program],
                            capture_output=True, env=env, timeout=90)
    if result.returncode:
        raise RuntimeError("Get-WinEvent could not read the test exports")
    return json.loads(result.stdout)


def arguments(exe, system, sys_pin, sys_id, application, app_pin, app_id, restart=None):
    args = [exe, "--wer-reports", system, "--sha256", sys_pin, "--system-record", str(sys_id),
            "--application-log", application, "--application-sha256", app_pin, "--application-record", str(app_id)]
    if restart is not None:
        args.extend(["--restart-record", str(restart)])
    return args


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def select(rows):
    for sys in rows["system"]:
        starts = [r for r in rows["restart"] if r["machine"] == sys["machine"] and r["stop"] == sys["stop"]
                  and 1 < int(sys["id"]) - int(r["id"]) < 8192]
        same = [r for r in rows["application"] if (r["guid"], r["stop"], r["machine"]) == (sys["guid"], sys["stop"], sys["machine"])]
        if len(starts) == 1 and 1 < len(same) < len(rows["application"]):
            return sys, starts[0], same
    raise ValueError("Supply exports containing a corroborating restart, repeated report, and a different application report")


def verify(exe, system, application, work):
    sys_pin, app_pin = digest(system), digest(application)
    rows = oracle(system, application)
    sys, restart, matching = select(rows)
    first, last = int(restart["id"]), int(sys["id"])
    app = matching[0]

    def run(app_row=app, report=last, anchor=None, sys_path=system, spin=sys_pin, app_path=application, apin=app_pin, code=0):
        cmd = arguments(exe, sys_path, spin, report, app_path, apin, app_row["id"], anchor)
        result = subprocess.run(cmd, capture_output=True, timeout=40)
        check(result.returncode == code and not result.stderr, "reader exit status")
        doc = json.loads(result.stdout)
        check(doc["schema"] == "kn.wer_report_comparison.v1" and not doc["same_host_boot_verified"] and
              not doc["dump_content_verified"] and not doc["source_authenticated"] and doc["attributed_cause"] is None, "attribution")
        assessment = doc["assessment"]
        check(assessment["candidate"] == "same_recorded_bugcheck_report" and "/dump_content_verified" in assessment["missing"],
              "missing incident evidence")
        for pointer in assessment["support"] + assessment["contrary"] + assessment["missing"]:
            value = doc
            for part in pointer.removeprefix("/").split("/"):
                value = value[part]
        return doc

    def check_row(row, expected):
        check(row["status"] == "observed" and row["wer_record_id"] == expected["id"] and row["wer_event_filetime"] == expected["time"]
              and row["wer_report_guid"] == expected["guid"] and row["computer_label_observed"] and row["win32_error"] is None
              and [row["wer_bugcheck_code"], *row["wer_bugcheck_parameters"]] == expected["stop"], "native WER properties")

    matched = 0
    for row in rows["application"]:
        same_guid, same_stop, same_machine = (row[k] == sys[k] for k in ("guid", "stop", "machine"))
        agrees = same_guid and same_stop and same_machine
        doc = run(row, code=0 if agrees else 1)
        check_row(doc["system_log"]["report"], sys)
        check_row(doc["application_log"]["report"], row)
        check(doc["system_log"]["wer_log_sha256"] == sys_pin and doc["application_log"]["wer_log_sha256"] == app_pin,
              "record addresses bind to their own archives")
        check(doc["report_pair"] == dict(status="matching_recorded_report" if agrees else "conflicting_report_fields",
                                         same_wer_report_id=same_guid, same_reported_stop=same_stop, same_recorded_computer=same_machine)
              and doc["restart_interval"] is None, "independent report fields")
        for key, agreement in (("same_wer_report_id", same_guid), ("same_reported_stop", same_stop), ("same_recorded_computer", same_machine)):
            check("/report_pair/" + key in doc["assessment"]["support" if agreement else "contrary"], "field-specific explanation")
        matched += int(agrees)
    full = run(anchor=first)
    span = full["restart_interval"]
    check_row(span["restart"], restart)
    check(span["coverage"] == "continuous_saved_system_records" and span["records_read"] == span["classified_records"] == last - first + 1
          and span["same_recorded_computer"] and span["same_reported_stop"] and span["restart_report_corroborated"]
          and span["wer_intervening_record"] is None, "complete same-label System interval")

    dropped = work / "gap.evtx"
    omitted = first + 1
    query = f"*[System[(EventRecordID >= {first} and EventRecordID <= {last}) and (EventRecordID < {omitted} or EventRecordID > {omitted})]]"
    subprocess.run(["wevtutil.exe", "epl", system, dropped, "/lf:true", "/q:" + query], check=True, capture_output=True, timeout=30)
    gap_pin = digest(dropped)
    gap = run(anchor=first, sys_path=dropped, spin=gap_pin, code=1)
    lost = gap["restart_interval"]
    check(gap["report_pair"] == full["report_pair"] and lost["restart"] == span["restart"] and lost["same_reported_stop"]
          and lost["coverage"] == "incomplete_record_coverage" and not lost["restart_report_corroborated"]
          and lost["records_read"] == span["records_read"] - 1, "lost interior record")
    check("/restart_interval/coverage" in gap["assessment"]["missing"] and "/restart_interval/same_reported_stop" in gap["assessment"]["support"],
          "missing coverage retained alongside a matching stop")
    later = next(r for r in rows["restart"] if int(r["id"]) > last and r["machine"] == sys["machine"])
    reverse = run(anchor=later["id"], code=1)
    check(reverse["report_pair"] == full["report_pair"] and reverse["restart_interval"]["coverage"] == "record_order_conflict",
          "later restart is a different candidate")
    before = [r for r in rows["restart"] if int(r["id"]) < first and r["machine"] == sys["machine"] and last - int(r["id"]) < 8192]
    if before:
        crossed = run(anchor=before[-1]["id"], code=1)["restart_interval"]
        check(crossed["wer_intervening_record"] is not None and not crossed["restart_report_corroborated"], "intervening restart retained")
    wrong = run(anchor=first, apin="0" * 64, code=1)
    check(wrong["application_log"]["status"] == "event_digest_mismatch" and wrong["report_pair"]["same_wer_report_id"] is None
          and wrong["restart_interval"] == span, "independent System evidence with a wrong Application pin")
    wrong = run(spin="0" * 64, code=1)
    check(wrong["system_log"]["status"] == "event_digest_mismatch" and wrong["application_log"]["report"] == full["application_log"]["report"],
          "independent Application evidence with a wrong System pin")
    absent = run(app_row={"id": int(rows["last_app"]) + 1}, code=1)
    check(absent["application_log"]["report"]["status"] == "record_not_found" and absent["application_log"]["report"]["win32_error"] == 259
          and absent["report_pair"]["same_reported_stop"] is None,
          "missing record")
    maximum = 2**64 - 1
    utility = subprocess.run(["wevtutil.exe", "qe", application, "/lf:true", f"/q:*[System[EventRecordID={maximum}]]", "/f:xml"],
                             capture_output=True, timeout=20)
    check(not utility.stdout.strip(), "supply an archive without a maximum-width record")
    wide = run(app_row={"id": maximum}, code=1)["application_log"]["report"]
    check(wide["wer_record_id"] == str(maximum) and wide["status"] == ("event_query_failed" if utility.returncode else "record_not_found")
          and wide["win32_error"] == (utility.returncode or 259), "maximum-width lookup preserves the native failure")
    shared = run(app_row=sys, app_path=system, apin=sys_pin, code=1)
    check(shared["report_pair"]["status"] == "shared_archive_input" and shared["application_log"]["report"]["status"] == "different_event_source",
          "same saved archive used for both channels")
    for arg in ("0", "-1", str(2**64)):
        bad = arguments(exe, system, sys_pin, last, application, app_pin, app["id"], arg)
        trial = subprocess.run(bad, capture_output=True, timeout=8)
        check(trial.returncode == 2 and not trial.stdout and b"--wer-reports" in trial.stderr, "malformed record ID")

    alias = work / "same-file"
    os.link(dropped, alias)
    for sys_path, app_path in ((dropped, application), (system, dropped)):
        cmd = arguments(exe, sys_path, gap_pin if sys_path == dropped else sys_pin, last, app_path,
                        gap_pin if app_path == dropped else app_pin, app["id"], first)
        with alias.open("ab") as stream:
            good = subprocess.run(cmd, stdout=stream, stderr=subprocess.PIPE, timeout=8)
            bad = subprocess.run([*cmd, "--invalid"], stdout=subprocess.PIPE, stderr=stream, timeout=8)
        check(good.returncode == bad.returncode == 2 and digest(dropped) == gap_pin, "redirected inputs protected")
    check(sys_pin == digest(system) and app_pin == digest(application), "original archives preserved")
    print(f"{matched} matching and {len(rows['application']) - matched} contrary Application records. "
          f"{span['records_read']} System records between selected endpoints, including both. Gap and alias controls passed.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--exe", required=True, type=Path)
    ap.add_argument("--system", required=True, type=Path)
    ap.add_argument("--application", required=True, type=Path)
    options = ap.parse_args()
    with tempfile.TemporaryDirectory(prefix="kn-wer-test-") as temp:
        verify(options.exe.resolve(), options.system.resolve(), options.application.resolve(), Path(temp))
