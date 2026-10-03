#include "../user/CommandInput.h"
#include "../user/McpJson.h"

#include <iostream>
#include <random>
#include <sstream>

int main(int argc, char** argv)
{
    if (argc == 2 && std::string(argv[1]) == "--validate-json-lines")
    {
        std::string line;
        while (std::getline(std::cin, line))
        {
            std::cout << (mcpjson::ValidateDocument(mcpjson::Utf8ToWide(line)) ? "1" : "0") << '\n';
        }
        return 0;
    }

    uint64_t passed = 0;
    uint64_t failed = 0;
    auto check = [&](bool condition, const char* name)
    {
        if (condition)
        {
            ++passed;
        }
        else
        {
            ++failed;
            if (failed <= 20)
            {
                std::cerr << "FAIL " << name << '\n';
            }
        }
    };
    std::mt19937_64 random(0x4b4e444247ull);
    for (size_t iteration = 0; iteration < 25000; ++iteration)
    {
        const uint64_t value = random();
        uint64_t parsed = 0;
        const std::wstring decimal = std::to_wstring(value);
        std::wostringstream hexadecimal;
        hexadecimal << std::hex << value;
        check(commandinput::ParseDigits(decimal, 10, &parsed) && parsed == value, "decimal roundtrip");
        check(commandinput::ParseDigits(hexadecimal.str(), 16, &parsed) && parsed == value, "hex roundtrip");
        check(!commandinput::ParseDigits(decimal + L"x", 10, &parsed), "numeric suffix");
        check(!commandinput::ParseUnsigned(L"-" + decimal, 10, &parsed), "unsigned sign");

        std::wstring text;
        const size_t length = static_cast<size_t>(random() % 96);
        for (size_t index = 0; index < length; ++index)
        {
            text.push_back(static_cast<wchar_t>(random() & 0xffff));
        }
        const std::wstring quoted = mcpjson::Quote(text);
        const std::wstring clean = mcpjson::SanitizeUtf16(text);
        check(mcpjson::ValidateDocument(quoted) && mcpjson::Unescape(quoted) == clean, "JSON UTF-16 roundtrip");
        check(mcpjson::Utf8ToWide(mcpjson::WideToUtf8(text)) == clean, "UTF-8 roundtrip");
        const std::wstring document = L"{\"key\":" + quoted + L",\"n\":" + decimal + L",\"nested\":[true,null,{}]}";
        std::wstring extracted;
        check(mcpjson::ValidateDocument(document) && mcpjson::GetString(document, L"key", &extracted) &&
            extracted == clean, "JSON object roundtrip");
        check(!mcpjson::ValidateDocument(document + L"false"), "JSON trailing document");
        check(!mcpjson::ValidateDocument(document.substr(0, document.size() - 1)), "JSON truncation");
        check(!mcpjson::ValidateDocument(L"{\"key\":0,\"\\u006bey\":" + quoted + L"}"), "escaped duplicate key");

        // Exercise arbitrary malformed input and all public lookup paths under ASan.
        const wchar_t alphabet[] = L"{}[],:\"\\-+eE0123456789truefalsnul \t\r\n";
        std::wstring malformed;
        for (size_t index = 0; index < length; ++index)
        {
            malformed += alphabet[random() % (sizeof(alphabet) / sizeof(alphabet[0]) - 1)];
        }
        const bool valid = mcpjson::ValidateDocument(malformed);
        const bool found = mcpjson::FindRawValue(malformed, L"key", &extracted);
        check(!found || valid, "lookup requires a complete document");
        size_t end = 0;
        (void)mcpjson::ScanValue(malformed, 0, &end);
        (void)mcpjson::GetString(malformed, L"key", &extracted);
    }
    check(mcpjson::ValidateDocument(std::wstring(64, L'[') + L"0" + std::wstring(64, L']')),
        "JSON supported nesting");
    check(!mcpjson::ValidateDocument(std::wstring(65, L'[') + L"0" + std::wstring(65, L']')),
        "JSON nesting bound");
    std::cout << "[command-parser.selftest] passed=" << passed << " failed=" << failed << '\n';
    return failed == 0 ? 0 : 1;
}
