#pragma once
#include <string>
#include <vector>

struct ImageSourceCollection
{
    std::wstring Status = L"unavailable", Issue, Id, ReportPath, ReportSha256, CapturePath, HeadSha256;
    std::wstring CaptureStatus, SourceStatus;
    bool ReportCommitted = false, Closed = false, Indexed = false;
};

ImageSourceCollection JournalProcessImageSource(const std::wstring& report, const std::wstring& pin,
    const std::wstring& imageCase, const std::wstring& store, const std::wstring& collectionId);
std::wstring ImageSourceCollectionJson(const ImageSourceCollection& collection);
int RunImageSourceCommand(const std::vector<std::wstring>& args, bool directJsonOutput);
