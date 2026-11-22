#include "DumpObservationSource.h"
#include "ContentHash.h"
#include "MemoryDumper.h"
#include "KnLiveDbgPaging.h"

#include <Windows.h>
#include <mindumpdef.h>
#include <cstring>
#include <mutex>

namespace
{
    constexpr uint64_t PhysicalMask = 0x000ffffffffff000ull;
    constexpr uint64_t PageBytes = 4096;
    static_assert(kCrashDumpHeaderBytes == DumpInitializationObservation::HeaderBytes, "initialization byte ceiling assumes a complete dump header");

    struct Run
    {
        uint64_t Base = 0;
        uint64_t Bytes = 0;
        uint64_t Offset = 0;
    };

    class CallbackObservationSource final : public IObservationSource
    {
    public:
        ObservationSourceCapabilities Caps;
        std::function<ObservationReadResult(const ObservationReadRequest&)> Reader;
        const ObservationSourceCapabilities& Capabilities() const override { return Caps; }
    protected:
        ObservationReadResult ReadSpans(const ObservationReadRequest& request) override { return Reader(request); }
    };

    template<class Read>
    ObservationReadState RecordInitializationRead(DumpInitializationObservation* init, uint32_t levels,
        const wchar_t* purpose, uint32_t length, std::vector<uint8_t>* bytes, Read read)
    {
        if (!init) { return read(nullptr); }
        ++init->Attempts;
        if (init->Reads.size() >= init->MaxReads || length > init->MaxRequestedBytes - init->ChargedBytes)
        {
            init->RecordingComplete = false;
            bytes->clear();
            return ObservationReadState::BudgetDeferred;
        }
        init->ChargedBytes += length;
        auto& receipt = init->Reads.emplace_back();
        receipt.Purpose = purpose;
        receipt.CandidateLevels = levels;
        receipt.RequestedBytes = length;
        receipt.StartedMs = GetTickCount64();
        receipt.State = read(&receipt);
        receipt.FinishedMs = GetTickCount64();
        if (receipt.DigestBytes && receipt.Sha256.empty()) { init->RecordingComplete = false; }
        return receipt.State;
    }

    class DumpFile
    {
    public:
        ~DumpFile()
        {
            if (Handle != INVALID_HANDLE_VALUE)
            {
                CloseHandle(Handle);
            }
        }

        bool Open(const std::wstring& path, DumpInitializationObservation* init, bool localDataOnly)
        {
            const auto reject = [&](const wchar_t* reason, std::optional<DWORD> status = std::nullopt)
            {
                if (init) { init->Decision = reason; init->QualificationError = status; }
                return false;
            };
            if (path.empty() || path.size() > 30000 || path.find(L'\0') != std::wstring::npos)
            {
                return reject(L"path_rejected");
            }
            std::wstring folded = path;
            for (auto& c : folded)
            {
                if (c >= L'a' && c <= L'z')
                {
                    c -= L'a' - L'A';
                }
            }
            if (folded.rfind(L"\\\\.\\", 0) == 0 || folded.rfind(L"\\\\?\\GLOBALROOT", 0) == 0)
            {
                return reject(L"path_rejected");
            }
            Handle = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                FILE_FLAG_RANDOM_ACCESS | FILE_FLAG_OPEN_REPARSE_POINT | (localDataOnly ? FILE_FLAG_OPEN_NO_RECALL : 0), nullptr);
            if (init) { init->OpenStatus = Handle == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS; }
            if (Handle == INVALID_HANDLE_VALUE) { return reject(L"file_open_failed"); }
            if (init) { SetLastError(ERROR_SUCCESS); }
            const DWORD type = GetFileType(Handle);
            if (type != FILE_TYPE_DISK)
            {
                const DWORD status = init && type == FILE_TYPE_UNKNOWN ? GetLastError() : ERROR_SUCCESS;
                return status ? reject(L"file_type_unavailable", status) : reject(L"not_disk_file");
            }
            if (!GetFileInformationByHandle(Handle, &Identity)) { return reject(L"file_identity_unavailable", GetLastError()); }
            if (Identity.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))
            { return reject(L"unsupported_file_attributes"); }
            constexpr DWORD recall = FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_OPEN | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;
            if (localDataOnly && (Identity.dwFileAttributes & recall)) { return reject(L"data_recall_required"); }
            Size = (uint64_t(Identity.nFileSizeHigh) << 32) | Identity.nFileSizeLow;
            FILETIME created{}, exited{}, kernel{}, user{};
            if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user))
            {
                return reject(L"collector_identity_unavailable", GetLastError());
            }
            static std::atomic<uint64_t> serial{0};
            Id = L"dump_handle:" + std::to_wstring(GetCurrentProcessId()) + L":" +
                std::to_wstring((uint64_t(created.dwHighDateTime) << 32) | created.dwLowDateTime) + L":" +
                std::to_wstring(++serial);
            return true;
        }

        bool Unchanged(DWORD* status = nullptr) const
        {
            BY_HANDLE_FILE_INFORMATION now{};
            const bool queried = GetFileInformationByHandle(Handle, &now) != FALSE;
            if (status) { *status = queried ? ERROR_SUCCESS : GetLastError(); }
            return queried && now.dwVolumeSerialNumber == Identity.dwVolumeSerialNumber &&
                now.nFileIndexHigh == Identity.nFileIndexHigh && now.nFileIndexLow == Identity.nFileIndexLow &&
                now.nFileSizeHigh == Identity.nFileSizeHigh && now.nFileSizeLow == Identity.nFileSizeLow &&
                CompareFileTime(&now.ftLastWriteTime, &Identity.ftLastWriteTime) == 0;
        }

        bool SameReadIdentity(DumpInitializationRead* receipt) const
        {
            DWORD status = ERROR_SUCCESS;
            const bool same = Unchanged(receipt ? &status : nullptr);
            if (receipt && !same) { receipt->IdentityFailureStatus = status; }
            return same;
        }

        ObservationReadState Read(uint64_t offset, uint32_t length, std::vector<uint8_t>* bytes,
            DumpInitializationRead* receipt = nullptr)
        {
            bytes->clear();
            if (receipt) { receipt->FileOffset = offset; }
            std::lock_guard<std::mutex> lock(Mutex);
            if (!SameReadIdentity(receipt))
            {
                return ObservationReadState::IdentityChanged;
            }
            if (length == 0 || offset > Size || length > Size - offset || offset > INT64_MAX)
            {
                return ObservationReadState::NotCaptured;
            }
            LARGE_INTEGER position{};
            position.QuadPart = static_cast<LONGLONG>(offset);
            DWORD copied = 0;
            bytes->resize(length);
            const bool positioned = SetFilePointerEx(Handle, position, nullptr, FILE_BEGIN) != FALSE;
            if (receipt) { receipt->SeekStatus = positioned ? ERROR_SUCCESS : GetLastError(); }
            const bool read = positioned && ReadFile(Handle, bytes->data(), length, &copied, nullptr);
            if (receipt && positioned)
            {
                receipt->ReadStatus = read ? ERROR_SUCCESS : GetLastError();
                receipt->TransferredBytes = copied;
            }
            const bool same = SameReadIdentity(receipt);
            if (receipt && same && read && copied && copied <= length)
            {
                receipt->DigestBytes = copied;
                ContentHash hash;
                if (hash.Add(bytes->data(), copied)) { receipt->Sha256 = hash.Finish(); }
            }
            if (!read || copied != length || !same)
            {
                bytes->clear();
                return same ? ObservationReadState::Failed : ObservationReadState::IdentityChanged;
            }
            return ObservationReadState::Complete;
        }

        ObservationReadState Physical(uint64_t address, uint32_t length, std::vector<uint8_t>* bytes,
            DumpInitializationRead* receipt = nullptr)
        {
            bytes->clear();
            if (receipt) { receipt->PhysicalAddress = address; }
            if (!SameReadIdentity(receipt))
            {
                return ObservationReadState::IdentityChanged;
            }
            for (const auto& run : Runs)
            {
                if (address >= run.Base && address - run.Base < run.Bytes && length <= run.Bytes - (address - run.Base))
                {
                    return Read(run.Offset + address - run.Base, length, bytes, receipt);
                }
            }
            return SameReadIdentity(receipt) ? ObservationReadState::NotCaptured : ObservationReadState::IdentityChanged;
        }

        ObservationReadResult PhysicalObserved(uint64_t address, uint32_t length)
        {
            ObservationReadResult result;
            ObservationReadSpan span{address, length, ObservationReadState::NotCaptured, {}};
            std::lock_guard<std::mutex> lock(Mutex);
            if (!Unchanged())
            {
                result.State = ObservationReadState::IdentityChanged;
                return result;
            }
            for (const auto& run : Runs)
            {
                if (address < run.Base || address - run.Base >= run.Bytes || length > run.Bytes - (address - run.Base)) { continue; }
                const uint64_t offset = run.Offset + address - run.Base;
                LARGE_INTEGER position{};
                position.QuadPart = static_cast<LONGLONG>(offset);
                result.NativeStatusDomain = L"win32";
                result.TransferredBytesKnown = true;
                result.BackendContract = L"win32_dump_file_read";
                result.BackendCopyAttemptKnown = true;
                span.State = ObservationReadState::Failed;
                if (!SetFilePointerEx(Handle, position, nullptr, FILE_BEGIN))
                {
                    result.NativeStatus = GetLastError();
                    break;
                }
                DWORD copied = 0;
                std::vector<uint8_t> bytes(length);
                result.BackendCopyAttempted = true;
                const bool read = ReadFile(Handle, bytes.data(), length, &copied, nullptr) != FALSE;
                result.NativeStatus = read ? ERROR_SUCCESS : GetLastError();
                result.TransferredBytes = copied;
                if (copied > length)
                {
                    result.ValidationReason = L"invalid_dump_copy_count";
                    break;
                }
                if (!read && copied == length)
                {
                    result.ValidationReason = L"failed_dump_read_with_full_count";
                    break;
                }
                if (copied != 0)
                {
                    span.RequestedBytes = copied;
                    span.State = ObservationReadState::Complete;
                    bytes.resize(copied);
                    span.Bytes = std::move(bytes);
                    if (copied < length)
                    {
                        result.Spans.push_back(std::move(span));
                        span = {address + copied, length - copied, ObservationReadState::Failed, {}};
                    }
                }
                break;
            }
            if (!Unchanged())
            {
                result.Spans.clear();
                result.State = ObservationReadState::IdentityChanged;
                result.ValidationReason = L"dump_identity_changed";
                return result;
            }
            result.Spans.push_back(std::move(span));
            return result;
        }

        uint64_t Size = 0;
        std::wstring Id;
        std::vector<Run> Runs;

    private:
        HANDLE Handle = INVALID_HANDLE_VALUE;
        BY_HANDLE_FILE_INFORMATION Identity{};
        std::mutex Mutex;
    };

    struct ProbeResult
    {
        const wchar_t* Reason;
        bool Matched = false;
    };

    ProbeResult Probe(DumpObservationSource& source, uint64_t list, uint32_t levels,
        DumpInitializationObservation* init, const wchar_t*& purpose)
    {
        const auto readExact = [&](uint64_t address, uint32_t length, std::vector<uint8_t>* bytes)
        {
            if (!init) { return ReadObservationExact(source, address, length, bytes); }
            const auto begin = static_cast<uint32_t>(init->Reads.size());
            std::optional<ObservationReadResult> original;
            const bool accepted = ReadObservationExactWithReceipt(source, address, length, bytes, &original);
            if (!original) { init->RecordingComplete = false; return false; }
            const auto count = static_cast<uint32_t>(init->Reads.size()) - begin;
            init->ProbeReads.push_back({purpose, levels, length, address, count ? begin + 1 : 0, count, accepted, std::move(*original)});
            return accepted;
        };
        if (!source.Capabilities().AddressSpace.KernelRange(list, 16) || (list & 7) != 0)
        {
            return {L"list_range_rejected"};
        }
        purpose = L"list_head";
        std::vector<uint8_t> bytes;
        if (!readExact(list, 16, &bytes))
        {
            return {L"list_read_incomplete"};
        }
        uint64_t first = 0, last = 0;
        std::memcpy(&first, bytes.data(), 8);
        std::memcpy(&last, bytes.data() + 8, 8);
        if ((first & 7) != 0 || (last & 7) != 0 ||
            !source.Capabilities().AddressSpace.KernelRange(first, 16) ||
            !source.Capabilities().AddressSpace.KernelRange(last, 16))
        {
            return {L"link_range_rejected"};
        }
        purpose = L"first_backlink";
        if (!readExact(first + 8, 8, &bytes))
        {
            return {L"first_backlink_incomplete"};
        }
        uint64_t back = 0;
        std::memcpy(&back, bytes.data(), 8);
        if (back != list) { return {L"first_backlink_mismatch"}; }
        purpose = L"last_forward_link";
        if (!readExact(last, 8, &bytes)) { return {L"last_forward_link_incomplete"}; }
        std::memcpy(&back, bytes.data(), 8);
        return back == list ? ProbeResult{L"matched", true} : ProbeResult{L"last_forward_link_mismatch"};
    }
}

DumpAddressTranslation TranslateDumpAddress(const DumpPhysicalReader& reader,
    uint64_t root, uint32_t pagingLevels, uint64_t address)
{
    DumpAddressTranslation result;
    const auto space = AddressSpaceDescriptor::FromPagingLevels(pagingLevels);
    if (!reader || !space.Canonical(address) ||
        (root & PhysicalMask) == 0 || (root & ~(PhysicalMask | 0xfffull)) != 0)
    {
        return result;
    }
    uint64_t table = root & PhysicalMask;
    for (uint32_t level = pagingLevels; level != 0; --level)
    {
        const uint32_t shift = 12 + 9 * (level - 1);
        const uint64_t index = (address >> shift) & 511;
        std::vector<uint8_t> bytes;
        result.State = reader(table + index * 8, 8, &bytes);
        if (result.State != ObservationReadState::Complete || bytes.size() != 8)
        {
            if (result.State == ObservationReadState::Complete)
            {
                result.State = ObservationReadState::Failed;
            }
            return result;
        }
        uint64_t entry = 0;
        std::memcpy(&entry, bytes.data(), 8);
        if ((entry & 1) == 0)
        {
            result.State = ObservationReadState::NotPresent;
            return result;
        }
        if (!KnDbgPresentPagingEntryValid(entry, level))
        {
            result.State = ObservationReadState::Unsupported;
            return result;
        }
        const bool leaf = level == 1 || ((level == 2 || level == 3) && (entry & 0x80) != 0);
        if (leaf)
        {
            result.MappingBytes = uint64_t(1) << shift;
            result.PhysicalAddress = (entry & PhysicalMask & ~(result.MappingBytes - 1)) + (address & (result.MappingBytes - 1));
            return result;
        }
        table = entry & PhysicalMask;
        if (table == 0)
        {
            result.State = ObservationReadState::Unsupported;
            return result;
        }
    }
    result.State = ObservationReadState::Unsupported;
    return result;
}

DumpObservationSource::DumpObservationSource(std::wstring sourceId, uint64_t root, uint32_t pagingLevels,
    DumpPhysicalReader reader, DumpObservedPhysicalReader observedReader)
    : Root(root), PagingLevels(pagingLevels), Reader(std::move(reader)), ObservedReader(std::move(observedReader))
{
    Caps.SourceId = std::move(sourceId);
    Caps.Consistency = L"offline_dump";
    Caps.AddressSpace = AddressSpaceDescriptor::FromPagingLevels(pagingLevels);
    if ((pagingLevels != 4 && pagingLevels != 5) || !Reader)
    {
        Caps.SourceId.clear();
    }
}

const ObservationSourceCapabilities& DumpObservationSource::Capabilities() const
{
    return Caps;
}

ObservationReadResult DumpObservationSource::ReadSpans(const ObservationReadRequest& request)
{
    ObservationReadResult result;
    uint32_t done = 0;
    while (done < request.Length)
    {
        ObservationReadSpan span;
        span.Address = request.Address + done;
        span.RequestedBytes = (std::min)(request.Length - done, uint32_t(PageBytes - (span.Address & (PageBytes - 1))));
        if (request.Cancellation != nullptr && request.Cancellation->load())
        {
            span.State = ObservationReadState::Cancelled;
        }
        else
        {
            const auto translation = TranslateDumpAddress(Reader, Root, PagingLevels, span.Address);
            span.State = translation.State;
            if (span.State == ObservationReadState::Complete)
            {
                span.State = Reader(translation.PhysicalAddress, span.RequestedBytes, &span.Bytes);
            }
        }
        if (span.State != ObservationReadState::Complete)
        {
            span.Bytes.clear();
        }
        if (span.State == ObservationReadState::IdentityChanged)
        {
            result.Spans.clear();
            result.Spans.push_back({request.Address, request.Length, ObservationReadState::IdentityChanged, {}});
            return result;
        }
        done += span.RequestedBytes;
        result.Spans.push_back(std::move(span));
    }
    return result;
}

DumpReadObservation DumpObservationSource::ReadWithReceipts(const ObservationReadRequest& request, ObservationOperationBudget budget)
{
    DumpReadObservation observed;
    observed.Source = Caps;
    observed.Request = request;
    observed.Request.Cancellation = nullptr;
    if (Caps.SourceId.empty() || Caps.SourceId.size() > 1900)
    {
        observed.Result.SourceId = Caps.SourceId;
        observed.Result.State = ObservationReadState::IdentityChanged;
        observed.Result.ValidationReason = L"invalid_dump_source_identity";
        return observed;
    }
    static std::atomic<uint64_t> serial{0};
    auto operation = std::make_shared<ObservationReadOperation>(L"dump_read:" + std::to_wstring(++serial),
        Caps.SourceId, Caps.SourceId + L":virtual", budget);
    CallbackObservationSource physical;
    physical.Caps.SourceId = Caps.SourceId + L":physical";
    physical.Caps.Consistency = L"offline_dump";
    physical.Caps.AddressDomain = ObservationAddressDomain::Physical;
    // This is the file format's address ceiling, not observed target MAXPHYADDR.
    physical.Caps.AddressSpace.PhysicalAddressBits = 52;
    physical.Reader = [&](const ObservationReadRequest& item)
    {
        if (ObservedReader) { return ObservedReader(item.Address, item.Length); }
        ObservationReadResult read;
        ObservationReadSpan span{item.Address, item.Length, ObservationReadState::Failed, {}};
        span.State = Reader(item.Address, item.Length, &span.Bytes);
        if (span.State != ObservationReadState::Complete) { span.Bytes.clear(); }
        read.Spans.push_back(std::move(span));
        return read;
    };
    RecordingObservationSource recorded(physical, operation);
    TranslationRootIdentity root;
    root.SourceId = physical.Caps.SourceId;
    root.TargetId = Caps.SourceId;
    root.AddressSpaceId = Caps.SourceId + L":virtual";
    root.RootId = Caps.SourceId + L":root";
    root.Binding = FileIdentityMatches ? L"dump_header_and_open_handle" : L"caller_declared_dump_root";
    root.Root = Root;
    root.Epoch = 1; // A reopened file receives a different SourceId.
    root.Space = Caps.AddressSpace;
    CallbackObservationSource virtualSource;
    virtualSource.Caps = Caps;
    virtualSource.Reader = [&](const ObservationReadRequest& item)
    {
        ObservationReadResult result;
        uint32_t done = 0;
        while (done < item.Length)
        {
            const uint64_t current = item.Address + done;
            const auto chunk = (std::min)(item.Length - done, static_cast<uint32_t>(PageBytes - (current & (PageBytes - 1))));
            auto translated = TranslateObservedAddress(recorded, root, [&]() { return root; }, current, chunk, item.Cancellation);
            const auto state = translated.State;
            const auto translatedAddress = translated.PhysicalAddress;
            observed.Translations.push_back(std::move(translated));
            if (state == ObservationReadState::Complete)
            {
                ObservationReadRequest physicalRequest;
                physicalRequest.SourceId = physical.Caps.SourceId;
                physicalRequest.Address = translatedAddress;
                physicalRequest.Length = chunk;
                physicalRequest.ByteBudget = chunk;
                physicalRequest.Cancellation = item.Cancellation;
                const auto data = recorded.Read(physicalRequest);
                result.CancellationObserved = result.CancellationObserved || data.CancellationObserved;
                result.OperationDeadlineExceeded = result.OperationDeadlineExceeded || data.OperationDeadlineExceeded;
                if (data.CancellationObserved || data.OperationDeadlineExceeded || data.Spans.empty())
                {
                    result.Spans.push_back({current, chunk, data.CancellationObserved ? ObservationReadState::Cancelled :
                        data.OperationDeadlineExceeded ? ObservationReadState::BudgetDeferred : data.State, {}});
                }
                else
                {
                    for (auto span : data.Spans)
                    {
                        span.Address = current + span.Address - translatedAddress;
                        result.Spans.push_back(std::move(span));
                    }
                }
            }
            else
            {
                result.Spans.push_back({current, chunk, state, {}});
            }
            if (result.Spans.back().State == ObservationReadState::IdentityChanged)
            {
                result.Spans = {{item.Address, item.Length, ObservationReadState::IdentityChanged, {}}};
                break;
            }
            done += chunk;
        }
        return result;
    };
    observed.Result = virtualSource.Read(request);
    observed.PhysicalReads = operation->Snapshot();
    observed.Result.OperationId = observed.PhysicalReads.OperationId;
    return observed;
}

std::unique_ptr<DumpObservationSource> OpenDumpObservationSource(const std::wstring& path, std::wstring* error,
    DumpInitializationObservation* initialization, std::wstring_view expectedHeaderSha256)
{
    if (initialization) { *initialization = {}; }
    std::wstring ignored;
    if (error == nullptr)
    {
        error = &ignored;
    }
    *error = L"unsupported or inaccessible dump file";
    const auto reject = [&](const wchar_t* decision, const wchar_t* explanation) -> std::unique_ptr<DumpObservationSource>
    {
        if (initialization) { initialization->Decision = decision; }
        *error = explanation;
        return {};
    };
    if (!expectedHeaderSha256.empty() && !initialization)
    {
        return reject(L"header_pin_requires_receipt", L"a pinned header requires an initialization receipt");
    }
    auto file = std::make_shared<DumpFile>();
    if (!file->Open(path, initialization, !expectedHeaderSha256.empty())) { return {}; }
    if (initialization)
    {
        initialization->SourceId = file->Id;
        initialization->FileBytes = file->Size;
        initialization->Reads.reserve(DumpInitializationObservation::MaxReads);
        initialization->ProbeReads.reserve(6);
    }
    std::vector<uint8_t> bytes;
    const auto headerRead = RecordInitializationRead(initialization, 0, L"dump_header", kCrashDumpHeaderBytes, &bytes,
        [&](DumpInitializationRead* receipt) { return file->Read(0, kCrashDumpHeaderBytes, &bytes, receipt); });
    if (headerRead != ObservationReadState::Complete)
    {
        return reject(L"header_read_incomplete", L"unsupported or inaccessible dump file");
    }
    if (!expectedHeaderSha256.empty())
    {
        const auto* digest = initialization->CompleteHeaderSha256();
        if (!digest)
        {
            return reject(L"header_digest_unavailable", L"unable to verify the dump header digest");
        }
        if (*digest != expectedHeaderSha256)
        {
            return reject(L"header_digest_mismatch", L"dump header digest differs from the supplied digest");
        }
    }
    DUMP_HEADER64 header{};
    static_assert(sizeof(header) == kCrashDumpHeaderBytes, "dump header size");
    std::memcpy(&header, bytes.data(), sizeof(header));
    const auto& block = header.PhysicalMemoryBlock;
    if (header.Signature != DUMP_SIGNATURE64 || header.ValidDump != DUMP_VALID_DUMP64 ||
        header.MachineImageType != IMAGE_FILE_MACHINE_AMD64 || header.DumpType != DUMP_TYPE_FULL ||
        block.NumberOfRuns == 0 || block.NumberOfRuns > kCrashDumpMaxPhysicalRuns ||
        (header.DirectoryTableBase & PhysicalMask) == 0 || (header.DirectoryTableBase & ~(PhysicalMask | 0xfffull)) != 0)
    {
        return reject(L"unsupported_header", L"unsupported or inaccessible dump file");
    }
    if (initialization) { initialization->HeaderModuleList = header.PsLoadedModuleList; }
    uint64_t offset = kCrashDumpHeaderBytes, pages = 0;
    for (uint32_t i = 0; i < block.NumberOfRuns; ++i)
    {
        const auto& item = block.Run[i];
        if (item.PageCount == 0 || item.BasePage > (PhysicalMask >> 12) ||
            item.PageCount > (1ull << 40) - item.BasePage || item.PageCount > (file->Size - offset) / PageBytes)
        {
            return reject(L"invalid_or_truncated_run", L"invalid, overlapping or truncated physical runs");
        }
        const Run run{item.BasePage * PageBytes, item.PageCount * PageBytes, offset};
        for (const auto& prior : file->Runs)
        {
            if (run.Base < prior.Base + prior.Bytes && prior.Base < run.Base + run.Bytes)
            {
                return reject(L"overlapping_runs", L"invalid, overlapping or truncated physical runs");
            }
        }
        pages += item.PageCount;
        offset += run.Bytes;
        file->Runs.push_back(run);
    }
    if (pages != block.NumberOfPages)
    {
        return reject(L"run_page_count_mismatch", L"physical page count disagrees with run inventory");
    }
    const DumpPhysicalReader reader = [file](uint64_t address, uint32_t length, std::vector<uint8_t>* out)
    {
        return file->Physical(address, length, out);
    };
    const auto probeDepth = [&](uint32_t levels)
    {
        const wchar_t* purpose = L"list_head";
        // Only this temporary source refers to the initialization report.
        DumpObservationSource probe(file->Id + L":probe" + std::to_wstring(levels), header.DirectoryTableBase, levels,
            [&](uint64_t address, uint32_t length, std::vector<uint8_t>* out) {
                return RecordInitializationRead(initialization, levels, purpose, length, out,
                    [&](DumpInitializationRead* receipt) { return file->Physical(address, length, out, receipt); });
            });
        return Probe(probe, header.PsLoadedModuleList, levels, initialization, purpose);
    };
    const auto four = probeDepth(4);
    const auto five = probeDepth(5);
    const bool probe4 = four.Matched, probe5 = five.Matched;
    if (initialization)
    {
        initialization->Probe4 = four.Reason;
        initialization->Probe5 = five.Reason;
        if (!initialization->RecordingComplete)
        {
            return reject(L"initialization_recording_incomplete", L"dump initialization receipts are incomplete");
        }
    }
    uint64_t cr3 = 0, cr4 = 0;
    if (header.KdSecondaryVersion == 2)
    {
        std::memcpy(&cr3, header.ContextRecord + 0x4d0 + 0x10, 8);
        std::memcpy(&cr4, header.ContextRecord + 0x4d0 + 0x18, 8);
    }
    const bool validCr4 = (cr4 & (1ull << 5)) != 0 && (cr4 >> 32) == 0;
    if (initialization && validCr4) { initialization->ContextLevels = (cr4 & (1ull << 12)) ? 5 : 4; }
    if (validCr4 && (cr3 & PhysicalMask) != 0 && (cr3 & PhysicalMask) != (header.DirectoryTableBase & PhysicalMask))
    {
        return reject(L"context_root_conflict", L"dump CR3 disagrees with the declared address space");
    }
    uint32_t levels = 0;
    if (validCr4)
    {
        levels = (cr4 & (1ull << 12)) != 0 ? 5 : 4;
        if ((levels == 4 && !probe4 && probe5) || (levels == 5 && !probe5 && probe4))
        {
            return reject(L"context_depth_conflict", L"dump CR4 disagrees with the captured page-table probe");
        }
    }
    else if (probe4 != probe5)
    {
        levels = probe5 ? 5 : 4;
    }
    if (levels == 0)
    {
        return reject(probe4 && probe5 ? L"depth_ambiguous" : L"depth_unavailable",
            L"dump paging depth is unavailable, ambiguous or changed");
    }
    DWORD identityStatus = ERROR_SUCCESS;
    const bool stable = file->Unchanged(initialization ? &identityStatus : nullptr);
    if (initialization)
    {
        initialization->FinalIdentityStatus = identityStatus;
        initialization->FinalIdentityMatched = stable;
    }
    if (!stable) { return reject(L"source_identity_changed", L"dump paging depth is unavailable, ambiguous or changed"); }
    if (initialization)
    {
        initialization->SelectedLevels = levels;
        initialization->Decision = validCr4 ? L"context_depth" : L"unique_probe";
    }
    error->clear();
    auto source = std::make_unique<DumpObservationSource>(file->Id, header.DirectoryTableBase, levels, reader,
        [file](uint64_t address, uint32_t length) { return file->PhysicalObserved(address, length); });
    source->FileIdentityMatches = [file](uint32_t& status) {
        DWORD win32 = ERROR_SUCCESS;
        const bool matched = file->Unchanged(&win32);
        status = win32;
        return matched;
    };
    return source;
}
