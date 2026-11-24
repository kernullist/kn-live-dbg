"""Verify a retained PE's embedded signature or its member in one explicitly pinned Windows catalog."""
from contextlib import ExitStack
import ctypes as c
from ctypes import wintypes as w
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import struct
import uuid

from etl_reader_process import WindowsFiles, file_hash
from retained_corpus import OutputCollision
from saved_etl_comparison import local_path, outputs_safe


CATALOG_LIMIT = 64 << 20
WTD_UI_NONE = 2
WTD_CHOICE_FILE, WTD_CHOICE_CATALOG = 1, 2
WTD_STATEACTION_VERIFY, WTD_STATEACTION_CLOSE = 1, 2
WTD_REVOCATION_CHECK_NONE, WTD_REVOCATION_CHECK_CHAIN = 0x10, 0x40
WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_DISABLE_MD2_MD4 = 0x1000, 0x2000
GUID = c.c_ubyte * 16
ACTION = GUID.from_buffer_copy(uuid.UUID("00aac56b-cd44-11d0-8cc2-00c04fc295ee").bytes_le)
# The PE SIP subject reported by CryptSIPRetrieveSubjectGuid on executable images.
PE_SUBJECT = GUID.from_buffer_copy(uuid.UUID("c689aab8-8e78-11d0-8c47-00c04fc295ee").bytes_le)


class SignatureInputError(ValueError):
    """A locally selected input cannot supply the named signature evidence."""


class FileInfo(c.Structure):
    _fields_ = [("size", w.DWORD), ("path", w.LPCWSTR), ("file", w.HANDLE), ("subject", c.POINTER(GUID))]


class CatalogInfo(c.Structure):
    _fields_ = [("size", w.DWORD), ("version", w.DWORD), ("catalog", w.LPCWSTR), ("tag", w.LPCWSTR),
                ("member", w.LPCWSTR), ("file", w.HANDLE), ("digest", w.LPVOID), ("digest_size", w.DWORD),
                ("catalog_context", w.LPVOID), ("admin", w.HANDLE)]


class SignatureSettings(c.Structure):
    _fields_ = [("size", w.DWORD), ("index", w.DWORD), ("flags", w.DWORD), ("secondary_count", w.DWORD),
                ("verified_index", w.DWORD), ("crypto_policy", w.LPVOID)]


class TrustData(c.Structure):
    _fields_ = [("size", w.DWORD), ("callback", w.LPVOID), ("sip", w.LPVOID), ("ui", w.DWORD),
                ("revocation", w.DWORD), ("choice", w.DWORD), ("info", w.LPVOID), ("action", w.DWORD),
                ("state", w.HANDLE), ("url", w.LPWSTR), ("flags", w.DWORD), ("ui_context", w.DWORD),
                ("settings", c.POINTER(SignatureSettings))]


# Only the common prefixes used to copy the leaf DER while the verified provider state is alive.
class CertContext(c.Structure):
    _fields_ = [("encoding", w.DWORD), ("der", w.LPVOID), ("length", w.DWORD)]


class ProviderCert(c.Structure):
    _fields_ = [("size", w.DWORD), ("context", c.POINTER(CertContext))]


class ProviderSigner(c.Structure):
    _fields_ = [("size", w.DWORD), ("verification_time", w.FILETIME), ("chain_length", w.DWORD),
                ("chain", w.LPVOID), ("signer_type", w.DWORD), ("signer_info", w.LPVOID), ("error", w.DWORD)]


class WinTrust:
    def __init__(self):
        library = c.WinDLL("wintrust.dll", winmode=0x800, use_last_error=True)  # LOAD_LIBRARY_SEARCH_SYSTEM32

        def api(name, result, *args):
            function = getattr(library, name)
            function.argtypes, function.restype = args, result
            return function

        self.verify = api("WinVerifyTrust", w.LONG, w.HWND, c.POINTER(GUID), c.POINTER(TrustData))
        self.provider = api("WTHelperProvDataFromStateData", w.LPVOID, w.HANDLE)
        self.signer = api("WTHelperGetProvSignerFromChain", c.POINTER(ProviderSigner), w.LPVOID, w.DWORD, w.BOOL, w.DWORD)
        self.cert = api("WTHelperGetProvCertFromChain", c.POINTER(ProviderCert), c.POINTER(ProviderSigner), w.DWORD)
        self.acquire = api("CryptCATAdminAcquireContext2", w.BOOL, c.POINTER(w.HANDLE), w.LPVOID, w.LPCWSTR, w.LPVOID, w.DWORD)
        self.member_hash = api("CryptCATAdminCalcHashFromFileHandle2", w.BOOL, w.HANDLE, w.HANDLE, c.POINTER(w.DWORD), w.LPVOID, w.DWORD)
        self.release = api("CryptCATAdminReleaseContext", w.BOOL, w.HANDLE, w.DWORD)
        crypto = c.WinDLL("crypt32.dll", winmode=0x800, use_last_error=True)
        self.subject = crypto.CryptSIPRetrieveSubjectGuid
        self.subject.argtypes, self.subject.restype = (w.LPCWSTR, w.HANDLE, c.POINTER(GUID)), w.BOOL

    def verify_signature(self, info, embedded, revocation, proof):
        data = TrustData()
        data.size, data.ui = c.sizeof(data), WTD_UI_NONE
        data.choice = WTD_CHOICE_FILE if embedded else WTD_CHOICE_CATALOG
        data.action = WTD_STATEACTION_VERIFY
        data.info = c.cast(c.pointer(info), w.LPVOID)
        # Cache-only retrieval, disable MD2/MD4; apply exactly the signed revocation policy.
        data.revocation = int(revocation == "cached_chain")
        data.flags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_DISABLE_MD2_MD4
        data.flags |= WTD_REVOCATION_CHECK_CHAIN if data.revocation else WTD_REVOCATION_CHECK_NONE
        settings = SignatureSettings(c.sizeof(SignatureSettings), 0, 1)  # WSS_VERIFY_SPECIFIC, primary signature
        settings.verified_index = 0xffffffff
        if embedded:
            data.settings = c.pointer(settings)
        try:
            status = self.verify(w.HWND(-1), c.byref(ACTION), c.byref(data))
            proof["wintrust_status"] = f"0x{status & 0xffffffff:08x}"
            if status != 0:
                return "wintrust_rejected"
            # Windows can leave the output index unset on a single signature. The request still
            # specifies index zero. Read the verified file signer's chain from this operation.
            if not data.state or (embedded and settings.verified_index not in (0, 0xffffffff)):
                return "verified_signer_unavailable"
            provider = self.provider(data.state)
            signer = self.signer(provider, 0, False, 0) if provider else None
            if (not signer or signer.contents.size < c.sizeof(ProviderSigner) or not signer.contents.chain_length or
                    signer.contents.error or signer.contents.signer_type & 0x10):  # SGNR_TYPE_TIMESTAMP
                return "verified_signer_unavailable"
            cert = self.cert(signer, 0)
            if not cert or cert.contents.size < c.sizeof(ProviderCert) or not cert.contents.context:
                return "verified_signer_unavailable"
            leaf = cert.contents.context.contents
            if not leaf.der or not 0 < leaf.length <= (1 << 20):
                return "verified_signer_unavailable"
            proof["signer_certificate_sha256"] = hashlib.sha256(c.string_at(leaf.der, leaf.length)).hexdigest()
            return "verified"
        finally:
            if data.state:
                data.action = WTD_STATEACTION_CLOSE
                self.verify(w.HWND(-1), c.byref(ACTION), c.byref(data))

    def verify_catalog(self, image, member_name, catalog_name, revocation, proof):
        import msvcrt
        handle = msvcrt.get_osfhandle(image.fileno())
        admin = w.HANDLE()
        if not self.acquire(c.byref(admin), None, "SHA256", None, 0):
            raise c.WinError(c.get_last_error())
        try:
            member = (c.c_ubyte * 32)()
            size = w.DWORD(c.sizeof(member))
            image.seek(0)
            if not self.member_hash(admin, handle, c.byref(size), member, 0) or size.value != c.sizeof(member):
                return "catalog_member_hash_unavailable"
            proof["catalog_member_sha256"] = bytes(member).hex()
            info = CatalogInfo()
            info.size, info.catalog, info.tag = c.sizeof(info), catalog_name, bytes(member).hex().upper()
            info.member, info.file, info.admin = member_name, handle, admin
            info.digest, info.digest_size = c.cast(member, w.LPVOID), size.value
            image.seek(0)
            return self.verify_signature(info, False, revocation, proof)
        finally:
            self.release(admin, 0)


def pinned_file(stack, files, name, limit):
    import msvcrt
    path = local_path(name)
    # Separate chains can have different identities even when their spelling differs only in case.
    files.parents(stack, path.parent, set(), share_directory_writes=False)
    stream = stack.enter_context(files.hold(path))
    if not outputs_safe((), stream):
        raise OutputCollision("an output aliases a Windows signature input")
    size = os.fstat(stream.fileno()).st_size
    if not 0 < size <= limit:
        raise SignatureInputError("signature_input_size_outside_limit")
    buf = c.create_unicode_buffer(32768)
    used = files.final_name(msvcrt.get_osfhandle(stream.fileno()), buf, len(buf), 1)  # VOLUME_NAME_GUID
    if not 0 < used < len(buf) or not buf.value.startswith("\\\\?\\Volume{"):
        raise SignatureInputError("signature_volume_path_unavailable")
    volume_path = Path(buf.value)
    files.parents(stack, volume_path.parent, set(), share_directory_writes=False)
    canonical = stack.enter_context(files.hold(volume_path))
    identities = []
    for opened in (stream, canonical):
        identity = (c.c_ubyte * 24)()  # FILE_ID_INFO: volume serial and 128-bit file ID.
        if not files.info(msvcrt.get_osfhandle(opened.fileno()), 18, identity, c.sizeof(identity)) or not any(identity[8:]):
            raise SignatureInputError("signature_file_identity_unavailable")
        identities.append(bytes(identity))
    if identities[0] != identities[1]:
        raise SignatureInputError("signature_input_changed")
    # Windows and Python both seek this handle. Keep a single unbuffered cursor for their reads.
    return canonical.raw, str(volume_path), size


def pe_header(stream, size):
    stream.seek(0)
    header = stream.read(64)
    if len(header) != 64 or header[:2] != b"MZ":
        return False
    offset, = struct.unpack_from("<I", header, 60)
    if not 64 <= offset <= size - 24:
        return False
    stream.seek(offset)
    return stream.read(4) == b"PE\0\0"


def check_files(image_path, image_pin, limit, catalog_path, policy, proof):
    import msvcrt
    files = WindowsFiles()
    with ExitStack() as stack:
        image, name, size = pinned_file(stack, files, image_path, limit)
        observed = file_hash(image)
        proof.update(reference_sha256=observed, reference_bytes=size)
        if observed != image_pin:
            return "reference_mismatch"
        if not pe_header(image, size):
            return "invalid_pe_reference"
        image.seek(0)
        trust = WinTrust()
        handle = msvcrt.get_osfhandle(image.fileno())
        subject = GUID()
        if not trust.subject(name, handle, c.byref(subject)) or bytes(subject) != bytes(PE_SUBJECT):
            return "unsupported_pe_subject"
        image.seek(0)
        catalog = None
        if policy["kind"] == "embedded":
            info = FileInfo(c.sizeof(FileInfo), name, handle, c.pointer(PE_SUBJECT))
            status = trust.verify_signature(info, True, policy["revocation"], proof)
        else:
            catalog, catalog_name, size = pinned_file(stack, files, catalog_path, CATALOG_LIMIT)
            observed = file_hash(catalog)
            proof.update(catalog_sha256=observed, catalog_bytes=size)
            if observed != policy["catalog_sha256"]:
                return "catalog_digest_mismatch"
            status = trust.verify_catalog(image, name, catalog_name, policy["revocation"], proof)
        if file_hash(image) != image_pin or (catalog is not None and file_hash(catalog) != policy["catalog_sha256"]):
            return "signature_input_changed"
        if status == "verified" and proof["signer_certificate_sha256"] != policy["signer_certificate_sha256"]:
            return "signer_certificate_mismatch"
        return status


def verify_reference(image_path, image_pin, limit, catalog_path, policy):
    proof = dict(signature_policy=policy, started_utc=datetime.now(timezone.utc).isoformat())
    if os.name != "nt":
        status = "windows_trust_unavailable"
    elif (catalog_path is not None) != (policy["kind"] == "catalog"):
        status = "catalog_required" if policy["kind"] == "catalog" else "unexpected_catalog"
    else:
        try:
            status = check_files(image_path, image_pin, limit, catalog_path, policy, proof)
        except OutputCollision:
            raise
        except SignatureInputError as exc:
            status = str(exc)
        except (OSError, ValueError, AttributeError) as exc:
            status = "windows_signature_input_or_provider_unavailable"
            proof["win32_status"] = getattr(exc, "winerror", None)
    proof.update(status=status, finished_utc=datetime.now(timezone.utc).isoformat())
    return proof
