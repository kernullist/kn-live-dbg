#include "EvidenceInvestigation.h"
#include "BundleObservationSource.h"
#include "ContentHash.h"
#include "KmonHuntingJson.h"
#include "AnalystSnapshot.h"

#include <filesystem>
#include <set>

namespace
{
    std::wstring HashText(const std::wstring& text)
    {
        const auto utf8 = mcpjson::WideToUtf8(text);
        ContentHash hash;
        return hash.Add(reinterpret_cast<const uint8_t*>(utf8.data()), utf8.size()) ? hash.Finish() : L"";
    }
    bool Successful(const EvidenceQueryResult& r) { return r.Status == L"ok" || r.Status == L"partial_inventory"; }
}

std::wstring EvidenceSessionJson(const EvidenceSessionSummary& s)
{
    if (s.CollectionId.empty() || s.CollectionId.size() > 128 || s.CollectionId.find(L'\0') != std::wstring::npos ||
        mcpjson::SanitizeUtf16(s.CollectionId) != s.CollectionId || s.Written > s.Admitted ||
        s.Failed != s.Admitted - s.Written || s.Bytes > 128ull * 1024 * 1024 || s.Written > s.Bytes) { return {}; }
    return L"{\"schema\":\"kmon.evidence_session.v1\",\"scope\":\"attempted_hunt_bundle_publications\",\"closed\":true,\"collection_id\":" +
        mcpjson::Quote(s.CollectionId) + L",\"admitted\":" + mcpjson::Quote(std::to_wstring(s.Admitted)) +
        L",\"written\":" + mcpjson::Quote(std::to_wstring(s.Written)) + L",\"failed\":" + mcpjson::Quote(std::to_wstring(s.Failed)) +
        L",\"dropped\":" + mcpjson::Quote(std::to_wstring(s.Dropped)) + L",\"bytes\":" + mcpjson::Quote(std::to_wstring(s.Bytes)) + L"}";
}

bool ParseEvidenceSession(const std::wstring& json, EvidenceSessionSummary* session)
{
    if (session == nullptr) { return false; }
    *session = {};
    if (json.size() > 32768 || !mcpjson::ValidateDocument(json)) { return false; }
    EvidenceSessionSummary parsed;
    const auto number = [&](const wchar_t* name, uint64_t* value)
    {
        std::wstring text;
        if (!mcpjson::GetString(json, name, &text)) { return false; }
        text += L":";
        size_t at = 0;
        return KmonHuntCursorNumber(text, &at, value) && at == text.size();
    };
    if (!mcpjson::GetString(json, L"collection_id", &parsed.CollectionId) || !number(L"admitted", &parsed.Admitted) ||
        !number(L"written", &parsed.Written) || !number(L"failed", &parsed.Failed) || !number(L"dropped", &parsed.Dropped) ||
        !number(L"bytes", &parsed.Bytes) || EvidenceSessionJson(parsed) != json) { return false; }
    *session = std::move(parsed);
    return true;
}

EvidenceQueryResult QueryEvidenceDirectory(const std::wstring& directory, const KmonHuntFilter& filter,
    const KmonHuntQueryOptions& options)
{
    EvidenceQueryResult result;
    result.Limit = options.Limit;
    if (options.Limit == 0 || options.Limit > 256 || filter.Role.size() > 128 ||
        filter.Role.find(L'\0') != std::wstring::npos || options.Cursor.size() > 1200)
    {
        result.Status = L"invalid_query";
        return result;
    }
    std::error_code error;
    std::filesystem::directory_iterator iterator(directory, error), end;
    if (error) { result.Status = L"unavailable"; result.InventoryComplete = false; return result; }
    std::vector<std::filesystem::path> paths;
    size_t entries = 0;
    while (iterator != end)
    {
        if (++entries > 4096) { result.InventoryComplete = false; break; }
        if (iterator->path().extension() == L".kncase" || iterator->path().extension() == L".knledger") { paths.push_back(iterator->path()); }
        iterator.increment(error);
        if (error) { result.InventoryComplete = false; break; }
    }
    std::sort(paths.begin(), paths.end());
    std::wstring inventory;
    std::vector<EvidenceCaseSummary> matches;
    std::set<std::wstring> seen;
    std::set<std::wstring> sessions;
    std::map<std::wstring, uint64_t> present;
    size_t bytes = 0;
    for (const auto& path : paths)
    {
        WIN32_FILE_ATTRIBUTE_DATA attributes = {};
        const bool regular = GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &attributes) &&
            (attributes.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0;
        const uint64_t size = (static_cast<uint64_t>(attributes.nFileSizeHigh) << 32) | attributes.nFileSizeLow;
        const uint64_t modified = (static_cast<uint64_t>(attributes.ftLastWriteTime.dwHighDateTime) << 32) | attributes.ftLastWriteTime.dwLowDateTime;
        const auto name = path.filename().wstring();
        inventory += mcpjson::Quote(name) + L":" + std::to_wstring(size) + L":" + std::to_wstring(modified) + L":";
        if (size > 64ull * 1024 * 1024 - bytes) { result.InventoryComplete = false; break; }
        if (path.extension() == L".knledger")
        {
            std::wstring json, failure;
            size_t read = 0;
            EvidenceSessionSummary session;
            const bool valid = regular && size <= 32768 &&
                ReadAnalystSnapshot(path.wstring(), &json, &failure, (std::min<size_t>)(32768, 64 * 1024 * 1024 - bytes), &read, true) &&
                ParseEvidenceSession(json, &session);
            bytes += read;
            inventory += valid ? HashText(json) : L"invalid";
            inventory += L"\n";
            if (!valid || !sessions.insert(session.CollectionId).second) { ++result.InvalidFiles; }
            else { result.Sessions.push_back(std::move(session)); }
            continue;
        }
        EvidenceBundle bundle;
        std::wstring digest, failure;
        size_t read = 0;
        const bool imported = regular && size <= EvidenceBundleMaxJsonBytes &&
            LoadEvidenceBundle(path.wstring(), &bundle, &failure, &digest, 64 * 1024 * 1024 - bytes, &read);
        bytes += read;
        if (!imported)
        {
            ++result.InvalidFiles;
            inventory += L"invalid\n";
            continue;
        }
        inventory += digest + L"\n";
        ++result.ImportedFiles;
        if (!seen.insert(digest).second) { ++result.DuplicateFiles; continue; }
        ++present[bundle.CollectionId];
        if (filter.Matches(bundle.Receipt.Reference))
        {
            matches.push_back({name, digest, bundle.CollectionId, bundle.Receipt, EvidenceReadSetComplete(bundle)});
        }
    }
    for (const auto& collection : present)
    {
        if (collection.first.empty() || sessions.count(collection.first) == 0) { ++result.UnclosedCollections; }
    }
    for (const auto& session : result.Sessions)
    {
        const uint64_t count = present[session.CollectionId];
        if (session.Written > count) { result.UnavailableWrittenBundles += session.Written - count; }
        if (session.Written < count) { ++result.InvalidFiles; }
    }
    result.InventoryDigest = HashText(inventory + (result.InventoryComplete ? L"complete" : L"partial"));
    if (result.InventoryDigest.size() != 64) { result.Status = L"unavailable"; result.InventoryComplete = false; return result; }
    result.Matched = matches.size();
    const auto scope = KmonHuntQueryScope(filter, options.Limit);
    if (!options.Cursor.empty())
    {
        const auto& cursor = options.Cursor;
        size_t at = 68;
        uint64_t offset = 0;
        if (cursor.size() < 69 || cursor.compare(0, 3, L"b1:") != 0 || cursor[67] != L':' ||
            !KmonHuntCursorNumber(cursor, &at, &offset) || offset == 0 || offset > 4096 || cursor.substr(at) != scope)
        {
            result.Status = L"invalid_cursor";
            return result;
        }
        if (cursor.substr(3, 64) != result.InventoryDigest) { result.Status = L"stale_cursor"; return result; }
        if (offset >= result.Matched) { result.Status = L"invalid_cursor"; return result; }
        result.Offset = static_cast<size_t>(offset);
    }
    const auto last = (std::min)(matches.size(), result.Offset + options.Limit);
    result.Cases.assign(matches.begin() + result.Offset, matches.begin() + last);
    if (last < matches.size()) { result.NextCursor = L"b1:" + result.InventoryDigest + L":" + std::to_wstring(last) + L":" + scope; }
    if (!result.InventoryComplete || result.InvalidFiles != 0 || result.UnavailableWrittenBundles != 0) { result.Status = L"partial_inventory"; }
    return result;
}

std::wstring EvidenceQueryJson(const EvidenceQueryResult& r, const KmonHuntFilter& filter)
{
    const bool ok = Successful(r);
    const size_t omitted = ok ? r.Matched - r.Offset - r.Cases.size() : 0;
    std::wstring json = L"{\"schema\":\"kmon.evidence_query.v1\",\"input_trust\":\"unverified_local_bundles\",\"query_scope\":\"validated_bundle_inventory\"";
    json += L",\"status\":" + mcpjson::Quote(r.Status) + L",\"inventory_digest\":" + mcpjson::Quote(r.InventoryDigest);
    json += L",\"matched\":" + (ok ? std::to_wstring(r.Matched) : L"null") + L",\"returned\":" + std::to_wstring(r.Cases.size());
    json += L",\"page_offset\":" + std::to_wstring(r.Offset) + L",\"omitted_by_budget\":" + (ok ? std::to_wstring(omitted) : L"null");
    json += L",\"filter_pid\":" + (filter.HasPid ? std::to_wstring(filter.ProcessId) : L"null") + L",\"filter_role\":" + mcpjson::Quote(filter.Role);
    json += L",\"invalid_files\":" + std::to_wstring(r.InvalidFiles) + L",\"duplicate_files\":" + std::to_wstring(r.DuplicateFiles);
    json += L",\"imported_files\":" + std::to_wstring(r.ImportedFiles) + L",\"inventory_complete\":" + (r.InventoryComplete ? L"true" : L"false");
    json += L",\"unclosed_collections\":" + std::to_wstring(r.UnclosedCollections) +
        L",\"publication_closure_known\":" + (ok && r.InventoryComplete && r.InvalidFiles == 0 &&
            r.UnavailableWrittenBundles == 0 && r.UnclosedCollections == 0 && !r.Sessions.empty() ? L"true" : L"false") +
        L",\"unavailable_written_bundles\":" + std::to_wstring(r.UnavailableWrittenBundles) + L",\"sessions\":[";
    bool firstSession = true;
    for (const auto& session : r.Sessions)
    {
        if (!firstSession) { json += L","; }
        firstSession = false;
        json += EvidenceSessionJson(session);
    }
    json += L"]";
    json += L",\"collection_complete\":false,\"next_cursor\":" + (r.NextCursor.empty() ? L"null" : mcpjson::Quote(r.NextCursor)) + L",\"cases\":[";
    bool first = true;
    for (const auto& row : r.Cases)
    {
        if (!first) { json += L","; }
        first = false;
        json += L"{\"file\":" + mcpjson::Quote(row.FileName) + L",\"evidence_id\":" + mcpjson::Quote(row.Digest) +
            L",\"collection_id\":" + mcpjson::Quote(row.CollectionId) + L",\"read_set_complete\":" +
            (row.ReadSetComplete ? L"true" : L"false") + L",\"receipt\":" + KmonHuntReceiptJson(row.Receipt) + L"}";
    }
    return json + L"]}";
}

EvidenceReplayResult ReplayEvidence(const EvidenceBundle& b)
{
    EvidenceReplayResult result;
    const auto& r = b.Receipt.Reference;
    BundleObservationSource source(b);
    const ObservationReader reader = [&](uint64_t address, size_t size, std::vector<uint8_t>* out)
    {
        return ReadObservationExact(source, address, size, out);
    };
    if (!b.ReferenceConsistent) { result.Gaps.push_back(L"original_reference_consistency_unconfirmed"); }
    if (!EvidenceReadSetComplete(b)) { result.Gaps.push_back(L"declared_read_set_incomplete_or_conflicting"); }
    if (b.Receipt.Disposition == L"identity_conflict" || b.Receipt.Disposition == L"future_event") { result.Gaps.push_back(b.Receipt.Disposition); }
    const bool page = KmonPageRole(r.Role) || r.Role == L"etw_stack_return";
    if (r.PageComparable || page)
    {
        std::vector<uint8_t> raw;
        if (!reader(r.Address & ~4095ull, 4096, &raw)) { result.PageDigest = L"missing_raw_page"; }
        else if (!r.PageComparable) { result.PageDigest = L"page_present_without_comparable_digest"; }
        else { result.PageDigest = ContentHash::Bytes(raw) == r.PageSha256 ? L"matches_stored_digest" : L"digest_mismatch"; }
        if (result.PageDigest != L"matches_stored_digest") { result.Gaps.push_back(result.PageDigest); }
    }
    if (page)
    {
        result.Chain.Termination = L"page_evidence_not_a_function_entry";
        result.ReferenceReached = result.PageDigest == L"matches_stored_digest";
        return result;
    }
    const uint64_t root = r.Root == 0 ? r.Address : r.Root;
    const bool pointer = r.Slot != 0 && KmonPointerReference(r.Role);
    result.Chain = pointer ? ResolveReferencedCodeTarget(root, r.Slot, reader, {}) : ResolveCodeTarget(root, reader, {});
    if (pointer)
    {
        result.Slot = result.Chain.ReferenceStable ? L"points_to_recorded_root" : L"missing_changed_or_conflicting";
        if (!result.Chain.ReferenceStable) { result.Gaps.push_back(L"pointer_slot_not_reconstructed"); }
    }
    result.ReferenceReached = std::any_of(result.Chain.Hops.begin(), result.Chain.Hops.end(), [&](const auto& hop)
    {
        return hop.Address == r.Address && !hop.Bytes.empty();
    });
    if (!result.ReferenceReached) { result.Gaps.push_back(L"recorded_reference_not_reached"); }
    if (result.Chain.Termination != L"no_supported_head_transfer" && result.Chain.Termination != L"trap")
    {
        result.Gaps.push_back(result.Chain.Termination);
    }
    return result;
}

std::wstring EvidenceReplayJson(const EvidenceBundle& b, const EvidenceReplayResult& r, const std::wstring& digest)
{
    std::wstring json = L"{\"schema\":\"kmon.evidence_replay.v1\",\"input_trust\":\"unverified_local_bundle\",\"evidence_id\":" + mcpjson::Quote(digest);
    json += L",\"claim\":\"stored_static_facts_only\",\"execution_observed\":false,\"communication_proven\":false,\"actor_attributed\":false";
    json += L",\"image_verification_replayed\":false,\"collection_complete\":false,\"collector_authenticated\":false";
    json += L",\"status\":" + mcpjson::Quote(r.Gaps.empty() ? L"replayed_declared_scope" : L"partial");
    json += L",\"provenance\":{\"acquisition\":" + mcpjson::Quote(b.Acquisition) + L",\"collection_id\":" + mcpjson::Quote(b.CollectionId) +
        L",\"source\":" + mcpjson::Quote(b.Receipt.Reference.Context.Source) + L",\"dependency_group\":" + mcpjson::Quote(b.Receipt.Reference.Context.DependencyGroup) + L"}";
    json += L",\"original_receipt\":" + KmonHuntReceiptJson(b.Receipt) + L",\"page_digest\":" + mcpjson::Quote(r.PageDigest);
    json += L",\"slot\":" + mcpjson::Quote(r.Slot) + L",\"termination\":" + mcpjson::Quote(r.Chain.Termination) + L",\"hops\":[";
    bool first = true;
    for (const auto& hop : r.Chain.Hops)
    {
        if (!first) { json += L","; }
        first = false;
        json += L"{\"address\":" + mcpjson::Quote(std::to_wstring(hop.Address)) + L",\"target\":" + mcpjson::Quote(std::to_wstring(hop.Target)) +
            L",\"bytes_read\":" + std::to_wstring(hop.Bytes.size()) + L"}";
    }
    json += L"],\"gaps\":[";
    first = true;
    for (const auto& gap : r.Gaps) { if (!first) { json += L","; } first = false; json += mcpjson::Quote(gap); }
    return json + L"],\"unfulfilled_requirements\":[\"trusted_reference_image_and_normalization_for_image_verification\","
        L"\"execution_telemetry_for_execution_claims\",\"authenticated_acquisition_for_source_trust\","
        L"\"independent_evidence_for_actor_attribution\"]}";
}
