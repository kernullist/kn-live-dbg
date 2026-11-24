"""Publish verified archive bytes through the same exclusive Windows handle that created them."""
from contextlib import ExitStack, contextmanager
import ctypes as c
from ctypes import wintypes as w
import os
import re
import shutil
import stat
import struct
import subprocess
import uuid

from etl_reader_process import file_hash
from owned_module_benchmark import check
from retained_corpus import OutputCollision
from saved_etl_comparison import outputs_safe


@contextmanager
def held(files, path, *, share_directory_writes=False):
    with ExitStack() as stack:
        files.parents(stack, path.parent, set(), share_directory_writes=share_directory_writes)
        stream = stack.enter_context(files.hold(path))
        if not outputs_safe((), stream):
            raise OutputCollision("output aliases an input")
        yield stream


def native_result(program, *args, timeout=180):
    # The installed executable stays leased. Never search an extracted directory for a program or DLL.
    return subprocess.run([str(program), "--offline", "!kmon", *map(str, args), "/json"], executable=program,
                          cwd=program.parent, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, timeout=timeout, creationflags=subprocess.CREATE_NO_WINDOW)


def verified_protection(result):
    check(result["schema"] == "kn.evidence_privacy.v1" and result["status"] == "ready" and
          result["root_acl_verified"] is True and type(result["efs_required"]) is bool,
          "an initialized private store is required")
    return result


@contextmanager
def replay_directory(workspace, prefix=".knapproval-replay-"):
    # Inherit the verified private parent's ACL. Windows mode 0700 would also grant Administrators access.
    directory = workspace / (prefix + uuid.uuid4().hex)
    directory.mkdir()
    identity = directory.stat(follow_symlinks=False)
    try:
        yield directory
    finally:
        check(directory.resolve(strict=True) == workspace.resolve(strict=True) / directory.name and
              os.path.samestat(identity, directory.stat(follow_symlinks=False)),
              "private replay directory identity changed")
        shutil.rmtree(directory)


class SecurityAttributes(c.Structure):
    _fields_ = [("size", w.DWORD), ("descriptor", w.LPVOID), ("inherit", w.BOOL)]


class RenameInfo(c.Structure):
    _fields_ = [("flags", w.DWORD), ("directory", w.HANDLE), ("length", w.DWORD), ("name", w.WCHAR * 1)]


def local_free(pointer):
    free = c.WinDLL("kernel32", use_last_error=True).LocalFree
    free.argtypes, free.restype = (w.HANDLE,), w.HANDLE
    free(pointer)


@contextmanager
def archive_descriptor(protection):
    convert = c.WinDLL("advapi32", use_last_error=True).ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes, convert.restype = (w.LPCWSTR, w.DWORD, c.POINTER(w.LPVOID), c.POINTER(w.DWORD)), w.BOOL
    sid = protection["owner_sid"]
    check(type(sid) is str and re.fullmatch(r"S-1-(?:[0-9]+-)*[0-9]+", sid), "invalid private store owner")
    sddl = f"O:{sid}D:P(A;;FA;;;{sid})" + ("" if sid == "S-1-5-18" else "(A;;FA;;;SY)")
    descriptor = w.LPVOID()
    if not convert(sddl, 1, c.byref(descriptor), None):
        raise c.WinError(c.get_last_error())
    try:
        yield descriptor
    finally:
        local_free(descriptor)


def descriptor_text(descriptor):
    convert = c.WinDLL("advapi32", use_last_error=True).ConvertSecurityDescriptorToStringSecurityDescriptorW
    convert.argtypes, convert.restype = (w.LPVOID, w.DWORD, w.DWORD, c.POINTER(w.LPVOID), c.POINTER(w.DWORD)), w.BOOL
    text = w.LPVOID()
    if not convert(descriptor, 1, 5, c.byref(text), None):  # OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
        raise c.WinError(c.get_last_error())
    try:
        return c.wstring_at(text)
    finally:
        local_free(text)


def verify_pending_file(files, stream, protection):
    import msvcrt
    handle = msvcrt.get_osfhandle(stream.fileno())
    info = os.fstat(stream.fileno())
    attributes = (w.DWORD * 2)()
    if not files.info(handle, 9, attributes, c.sizeof(attributes)):
        raise c.WinError(c.get_last_error())
    forbidden = 0x10 | 0x400 | 0x1000 | 0x40000 | 0x400000  # Directory, reparse, offline or recall.
    check(stat.S_ISREG(info.st_mode) and info.st_ino and info.st_nlink == 1 and not attributes[0] & forbidden,
          "pending archive must be a single local file")
    check(bool(attributes[0] & stat.FILE_ATTRIBUTE_ENCRYPTED) == protection["efs_required"],
          "pending file encryption does not match the private store")

    # A rename carries every NTFS stream, even though the report authenticates only the unnamed stream.
    streams = c.create_string_buffer(4096)
    default_name = "::$DATA".encode("utf-16-le")
    check(files.info(handle, 7, streams, len(streams)), "pending file streams could not be verified")
    following, name_bytes, size = struct.unpack_from("<IIq", streams)
    check(not following and name_bytes == len(default_name) and size == info.st_size and
          streams.raw[24:24 + name_bytes] == default_name, "pending archive has unexpected data streams")

    get_security = c.WinDLL("advapi32", use_last_error=True).GetKernelObjectSecurity
    get_security.argtypes, get_security.restype = (w.HANDLE, w.DWORD, w.LPVOID, w.DWORD, c.POINTER(w.DWORD)), w.BOOL
    actual, needed = c.create_string_buffer(65536), w.DWORD()
    if not get_security(handle, 5, actual, len(actual), c.byref(needed)):
        raise c.WinError(c.get_last_error())
    with archive_descriptor(protection) as expected:
        check(descriptor_text(actual) == descriptor_text(expected), "pending archive owner or ACL changed")


def create_private_handle(files, path, protection):
    with archive_descriptor(protection) as descriptor:
        security = SecurityAttributes(c.sizeof(SecurityAttributes), descriptor, False)
        # GENERIC_READ | GENERIC_WRITE | DELETE, no sharing, CREATE_NEW.
        handle = files.create(str(path), 0xc0010000, 0, c.byref(security), 1, 0x80, None)
    if handle == c.c_void_p(-1).value:
        raise c.WinError(c.get_last_error())
    return handle


@contextmanager
def private_archive_stream(files, path, protection, *, create=False):
    import msvcrt
    if create:
        handle = create_private_handle(files, path, protection)
    else:
        # Open the reparse point itself, with no sharing. Recovery never truncates a candidate.
        handle = files.create(str(path), 0xc0010000, 0, None, 3, 0x00200000 | 0x00100000, None)
        if handle == c.c_void_p(-1).value:
            raise c.WinError(c.get_last_error())
    try:
        fd = msvcrt.open_osfhandle(handle, os.O_RDWR | os.O_BINARY)
    except BaseException:
        files.close(handle)
        raise
    with os.fdopen(fd, "r+b") as stream:
        if not outputs_safe((), stream):
            raise OutputCollision("output aliases a pending file")
        verify_pending_file(files, stream, protection)
        yield stream


def set_file_info(handle, kind, value):
    set_info = c.WinDLL("kernel32", use_last_error=True).SetFileInformationByHandle
    set_info.argtypes, set_info.restype = (w.HANDLE, c.c_int, w.LPVOID, w.DWORD), w.BOOL
    if not set_info(handle, kind, c.byref(value), c.sizeof(value)):
        raise c.WinError(c.get_last_error())


def discard_private_copy(stream):
    import msvcrt
    set_file_info(msvcrt.get_osfhandle(stream.fileno()), 4, c.c_ubyte(1))


def extend_sparse_file(stream, end):
    import msvcrt
    stream.seek(end)
    stream.flush()
    # FileEndOfFileInfo preserves a sparse hole. The Windows CRT's truncate can write zeros here.
    set_file_info(msvcrt.get_osfhandle(stream.fileno()), 6, c.c_longlong(end))


def check_archive_name(destination):
    name = destination.name.casefold()
    check(name not in ("store.knprivacy", "store.knstorelock") and
          not name.startswith((".knapprovalarchive.pending-", ".kniatarchive.pending-", ".kniat-recover-")),
          "archive destination is reserved for store control or temporary files")


def seal_archive(stream, destination, expected, *, before_rename=None):
    import msvcrt
    stream.flush()
    os.fsync(stream.fileno())
    check(file_hash(stream) == expected, "sealed bytes differ from the verified archive")
    if before_rename is not None:
        before_rename()
    name = str(destination).encode("utf-16-le")
    buffer = c.create_string_buffer(RenameInfo.name.offset + len(name) + 2)
    info = RenameInfo.from_buffer(buffer)
    info.length = len(name)
    c.memmove(c.addressof(buffer) + RenameInfo.name.offset, name, len(name))
    # FileRenameInfo, ReplaceIfExists false. Keep the verified handle exclusive through publication.
    set_file_info(msvcrt.get_osfhandle(stream.fileno()), 3, buffer)


def publish_archive(destination, files, protection, write, *, pending_prefix=".knapprovalarchive.pending-"):
    import msvcrt
    check_archive_name(destination)
    pending = destination.with_name(pending_prefix + uuid.uuid4().hex)
    handle = create_private_handle(files, pending, protection)
    fd, published = None, False
    try:
        attrs = (w.DWORD * 2)()
        if not files.info(handle, 9, attrs, c.sizeof(attrs)):
            raise c.WinError(c.get_last_error())
        check(not protection["efs_required"] or attrs[0] & 0x4000, "private archive did not inherit EFS")
        fd = msvcrt.open_osfhandle(handle, os.O_RDWR | os.O_BINARY)
        with os.fdopen(fd, "w+b", closefd=False) as stream:
            result = write(stream)
            seal_archive(stream, destination, result["archive_sha256"])
            published = True
        return result
    finally:
        try:
            if not published:
                set_file_info(handle, 4, c.c_ubyte(1))  # FileDispositionInfo
        finally:
            if fd is None:
                files.close(handle)
            else:
                os.close(fd)
