#pragma once
#include <cstdint>

int RunMcpToolCatalogSelfTest();
int RunMcpTransportSelfTest(bool observe = false);
int RunMcpJournalFixture(const wchar_t* directory, uint16_t port);
