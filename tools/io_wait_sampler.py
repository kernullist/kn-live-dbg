"""Project the issuing thread's documented SystemProcessInformation fields on Windows x64."""
import ctypes
from ctypes import wintypes as w
import struct
import time


TIMEOUT, FAILED = 258, 0xffffffff
LENGTH_MISMATCH = 0xc0000004
MAX_BUFFER = 32 << 20


def thread_row(data, length, pid, tid):
    # Windows SDK winternl.h, native x64: process header 256 bytes, thread row 80.
    # Image names, addresses, reserved fields and unrelated threads never leave this buffer.
    offset, found, seen_process = 0, None, False
    while True:
        if offset + 256 > length or length > len(data):
            return "invalid_layout", None
        stride, count = struct.unpack_from("<II", data, offset)
        end = offset + stride if stride else length
        if (stride and stride % 8) or end > length or offset + 256 + count*80 > end:
            return "invalid_layout", None
        owner, = struct.unpack_from("<Q", data, offset+80)
        if owner == pid:
            if seen_process:
                return "duplicate_process", None
            seen_process = True
            for pos in range(offset+256, offset+256+count*80, 80):
                thread_pid, thread_id = struct.unpack_from("<QQ", data, pos+40)
                if thread_id != tid:
                    continue
                if thread_pid != owner or found is not None:
                    return "conflicting_thread", None
                state, reason = struct.unpack_from("<II", data, pos+68)
                found = dict(process_id=owner, client_process_id=thread_pid, client_thread_id=thread_id,
                             thread_state=state, raw_wait_reason=reason,
                             native_fields=dict(process_offset=offset, thread_index=(pos-offset-256)//80,
                                                process_header_le=data[offset:offset+8].hex(), owner_le=data[offset+80:offset+88].hex(),
                                                client_id_le=data[pos+40:pos+56].hex(), state_reason_le=data[pos+68:pos+76].hex()))
        if not stride:
            return ("found", found) if found else ("thread_absent" if seen_process else "process_absent", None)
        offset = end


class ThreadSampler:
    def __init__(self):
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)

        def api(name, result, *args):
            fn = getattr(kernel, name)
            fn.argtypes, fn.restype = args, result
            return fn

        self.open = api("OpenThread", w.HANDLE, w.DWORD, w.BOOL, w.DWORD)
        self.pid = api("GetProcessIdOfThread", w.DWORD, w.HANDLE)
        self.tid = api("GetThreadId", w.DWORD, w.HANDLE)
        self.times = api("GetThreadTimes", w.BOOL, w.HANDLE, *(ctypes.POINTER(w.FILETIME),)*4)
        self.close = api("CloseHandle", w.BOOL, w.HANDLE)
        self.wait = api("WaitForSingleObject", w.DWORD, w.HANDLE, w.DWORD)
        self.clock = api("GetTickCount64", ctypes.c_uint64)
        self.query = ctypes.WinDLL("ntdll").NtQuerySystemInformation
        self.query.argtypes = (w.ULONG, w.LPVOID, w.ULONG, ctypes.POINTER(w.ULONG))
        self.query.restype = w.LONG
        self.data = bytearray(1 << 20)

    def bind(self, stack, plan):
        handle = self.open(0x100000 | 0x0800, False, plan["tid"])  # SYNCHRONIZE | THREAD_QUERY_LIMITED_INFORMATION
        if not handle:
            return None, dict(status="open_failed", win32_error=ctypes.get_last_error())
        stack.callback(self.close, handle)
        times = [w.FILETIME() for _ in range(4)]
        pid = self.pid(handle)
        tid = self.tid(handle) if pid else 0
        if not tid or not self.times(handle, *(ctypes.byref(t) for t in times)):
            return None, dict(status="identity_unavailable", win32_error=ctypes.get_last_error())
        created = str(times[0].dwHighDateTime << 32 | times[0].dwLowDateTime)
        matched = (pid, tid, created) == (plan["pid"], plan["tid"], plan["thread_created"])
        return (handle if matched else None), dict(status="bound" if matched else "generation_mismatch", win32_error=0,
                                                  owner_pid=pid, thread_id=tid, thread_created=created)

    def live(self, handle, timeout=0):
        result = self.wait(handle, timeout)
        return dict(result=result, win32_error=ctypes.get_last_error() if result == FAILED else 0)

    def snapshot(self, handle, pid, tid, slot):
        before = self.live(handle)
        attempts, row, lookup = [], None, "not_queried"
        begin = self.clock()
        if before["result"] == TIMEOUT:
            for _ in range(5):
                returned = w.ULONG()
                buf = (ctypes.c_ubyte * len(self.data)).from_buffer(self.data)
                status = self.query(5, buf, len(self.data), ctypes.byref(returned)) & 0xffffffff
                attempts.append(dict(buffer_bytes=len(self.data), returned_bytes=returned.value, ntstatus=status))
                if status == 0:
                    lookup, row = thread_row(self.data, returned.value, pid, tid)
                    break
                lookup = "query_failed"
                if status != LENGTH_MISMATCH:
                    break
                size = max(2*len(self.data), returned.value)
                if size > MAX_BUFFER:
                    lookup = "buffer_limit"
                    break
                self.data = bytearray(size)
        end = self.clock()
        return dict(slot=slot, start_tick_ms=str(begin), end_tick_ms=str(end), before=before,
                    after=self.live(handle), native_calls=attempts, lookup=lookup, thread_row=row)


def prepare(machine):
    if ctypes.sizeof(ctypes.c_void_p) != 8 or machine not in ("amd64", "x86_64"):
        return None, None
    try:
        return ThreadSampler(), None
    except (AttributeError, OSError) as exc:
        return None, getattr(exc, "winerror", None) or 127


def observe(child, stack, plan, interval_ms, limit, deadline, prepared):
    result = dict(binding=None, samples=[], stopped="unsupported_layout", terminal_wait=None)
    api, error = prepared
    if api is None:
        if error:
            result.update(binding=dict(status="api_unavailable", win32_error=error), stopped="thread_unbound")
        return result
    handle, result["binding"] = api.bind(stack, plan)
    if handle is None:
        result["stopped"] = "thread_unbound"
        return result
    while len(result["samples"]) < limit:
        if time.monotonic() >= deadline:
            result["stopped"] = "deadline"
            return result
        row = api.snapshot(handle, child.pid, plan["tid"], len(result["samples"])+1)
        result["samples"].append(row)
        terminal, phase = row["after"], "after_sample"
        if terminal["result"] == TIMEOUT and len(result["samples"]) < limit:
            # Wait on this retained thread, so a short capture does not sleep past its exit.
            terminal, phase = api.live(handle, interval_ms), "between_samples"
        if terminal["result"] != TIMEOUT:
            result["stopped"] = "thread_ended" if terminal["result"] == 0 else "liveness_unavailable"
            result["terminal_wait"] = dict(sample_slot=row["slot"], phase=phase, tick_ms=str(api.clock()), wait=terminal)
            return result
    result["stopped"] = "sample_limit"
    return result
