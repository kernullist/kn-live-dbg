#pragma once
#include <cstdint>
#include "McpObserveGrant.h"

int RunMcpToolCatalogSelfTest();
int RunMcpTransportSelfTest(bool observe = false);
int RunMcpJournalTransportFixture(const std::wstring& directory);
int RunMcpJournalFixture(const wchar_t* directory, uint16_t port, const std::vector<McpObserveGrant>& grants, uint32_t targetSessionSeconds, bool tls);
