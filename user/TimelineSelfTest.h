#pragma once

#include <cstdint>
#include <iosfwd>
#include <string>

int RunTimelineSelfTest();
bool ProcessHandleObserverSelfTest(bool emit);
bool CollectorProcessHandleFixture(uintptr_t inherited, bool retention);
void ReportKmonInventoryHandleFixture(uint32_t pid, const std::wstring& image, std::wostream& out);
void ReportHuntMetadataHandleFixture(uint32_t pid, uint64_t created, const std::wstring& image, std::wostream& out);
