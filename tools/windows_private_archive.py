"""Publish verified archive bytes through the same exclusive Windows handle that created them."""
import ctypes as c
from ctypes import wintypes as w
import os
import re
import uuid

from etl_reader_process import file_hash
from owned_module_benchmark import check


class SecurityAttributes(c.Structure):
    _fields_ = [("size", w.DWORD), ("descriptor", w.LPVOID), ("inherit", w.BOOL)]


class RenameInfo(c.Structure):
    _fields_ = [("flags", w.DWORD), ("directory", w.HANDLE), ("length", w.DWORD), ("name", w.WCHAR * 1)]


def publish_archive(destination, files, protection, write):
    import msvcrt
    kernel = c.WinDLL("kernel32", use_last_error=True)
    convert = c.WinDLL("advapi32", use_last_error=True).ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes, convert.restype = (w.LPCWSTR, w.DWORD, c.POINTER(w.LPVOID), c.POINTER(w.DWORD)), w.BOOL
    free = kernel.LocalFree
    free.argtypes, free.restype = (w.HANDLE,), w.HANDLE
    set_info = kernel.SetFileInformationByHandle
    set_info.argtypes, set_info.restype = (w.HANDLE, c.c_int, w.LPVOID, w.DWORD), w.BOOL

    sid = protection["owner_sid"]
    check(type(sid) is str and re.fullmatch(r"S-1-(?:[0-9]+-)*[0-9]+", sid), "invalid private store owner")
    sddl = f"O:{sid}D:P(A;;FA;;;{sid})" + ("" if sid == "S-1-5-18" else "(A;;FA;;;SY)")
    descriptor = w.LPVOID()
    if not convert(sddl, 1, c.byref(descriptor), None):
        raise c.WinError(c.get_last_error())
    try:
        security = SecurityAttributes(c.sizeof(SecurityAttributes), descriptor, False)
        pending = destination.with_name(f".knapprovalarchive.pending-{uuid.uuid4().hex}")
        # GENERIC_READ | GENERIC_WRITE | DELETE, no sharing, CREATE_NEW.
        handle = files.create(str(pending), 0xc0010000, 0, c.byref(security), 1, 0x80, None)
        if handle == c.c_void_p(-1).value:
            raise c.WinError(c.get_last_error())
    finally:
        free(descriptor)

    fd, published = None, False
    try:
        attrs = (w.DWORD * 2)()
        if not files.info(handle, 9, attrs, c.sizeof(attrs)):
            raise c.WinError(c.get_last_error())
        check(not protection["efs_required"] or attrs[0] & 0x4000, "private archive did not inherit EFS")
        fd = msvcrt.open_osfhandle(handle, os.O_RDWR | os.O_BINARY)
        with os.fdopen(fd, "w+b", closefd=False) as stream:
            result = write(stream)
            stream.flush()
            os.fsync(fd)
            check(file_hash(stream) == result["archive_sha256"], "sealed bytes differ from the verified archive")
        name = str(destination).encode("utf-16-le")
        buffer = c.create_string_buffer(RenameInfo.name.offset + len(name) + 2)
        info = RenameInfo.from_buffer(buffer)
        info.length = len(name)
        c.memmove(c.addressof(buffer) + RenameInfo.name.offset, name, len(name))
        # FileRenameInfo, ReplaceIfExists false. The verified handle remains exclusive through publication.
        if not set_info(handle, 3, buffer, len(buffer)):
            raise c.WinError(c.get_last_error())
        published = True
        return result
    finally:
        try:
            if not published:
                remove = c.c_ubyte(1)
                if not set_info(handle, 4, c.byref(remove), c.sizeof(remove)):  # FileDispositionInfo
                    raise c.WinError(c.get_last_error())
        finally:
            if fd is None:
                files.close(handle)
            else:
                os.close(fd)
