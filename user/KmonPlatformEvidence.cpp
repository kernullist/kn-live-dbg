#include "KmonPlatformEvidence.h"

#include <Windows.h>
#include <winternl.h>
#include <bcrypt.h>
#include <tbs.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <set>
#include <utility>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "tbs.lib")

namespace
{
    constexpr size_t kMaximumCiToolBytes = 256 * 1024;
    constexpr DWORD kCiToolTimeoutMs = 3000;
    constexpr size_t kMaximumBootLogBytes = 4 * 1024 * 1024;
    constexpr size_t kMaximumPolicies = 512;
    constexpr size_t kMaximumQuoteBytes = 64 * 1024;
    constexpr uint64_t kRequestLifetimeSeconds = 120;

    class OwnedHandle
    {
    public:
        OwnedHandle() = default;
        explicit OwnedHandle(HANDLE handle) : handle_(handle)
        {
        }

        ~OwnedHandle()
        {
            Reset();
        }

        OwnedHandle(const OwnedHandle&) = delete;
        OwnedHandle& operator=(const OwnedHandle&) = delete;

        HANDLE Get() const
        {
            return handle_;
        }

        bool Valid() const
        {
            return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
        }

        void Reset(HANDLE handle = nullptr)
        {
            if (Valid())
            {
                CloseHandle(handle_);
            }
            handle_ = handle;
        }

    private:
        HANDLE handle_ = nullptr;
    };

    struct AlgorithmOwner
    {
        BCRYPT_ALG_HANDLE Handle = nullptr;
        ~AlgorithmOwner()
        {
            if (Handle != nullptr)
            {
                BCryptCloseAlgorithmProvider(Handle, 0);
            }
        }
    };

    struct KeyOwner
    {
        BCRYPT_KEY_HANDLE Handle = nullptr;
        ~KeyOwner()
        {
            if (Handle != nullptr)
            {
                BCryptDestroyKey(Handle);
            }
        }
    };

    struct TbsContextOwner
    {
        TBS_HCONTEXT Handle = nullptr;
        ~TbsContextOwner()
        {
            if (Handle != nullptr)
            {
                Tbsip_Context_Close(Handle);
            }
        }
    };

    struct AttributeListOwner
    {
        std::vector<uint8_t> Storage;
        LPPROC_THREAD_ATTRIBUTE_LIST List = nullptr;
        ~AttributeListOwner()
        {
            if (List != nullptr)
            {
                DeleteProcThreadAttributeList(List);
            }
        }
    };

    struct ChildProcessCleanup
    {
        HANDLE Process = nullptr;
        bool Exited = false;
        ~ChildProcessCleanup()
        {
            if (Process != nullptr && !Exited)
            {
                TerminateProcess(Process, ERROR_CANCELLED);
            }
        }
    };

    std::wstring HexNumber(uint64_t value)
    {
        wchar_t text[32] = {};
        swprintf_s(text, L"0x%llx", static_cast<unsigned long long>(value));
        return text;
    }

    std::wstring HexBytes(const std::vector<uint8_t>& bytes)
    {
        static constexpr wchar_t digits[] = L"0123456789abcdef";
        std::wstring result;
        result.reserve(bytes.size() * 2);
        for (const uint8_t byte : bytes)
        {
            result.push_back(digits[byte >> 4]);
            result.push_back(digits[byte & 15]);
        }
        return result;
    }

    std::wstring Boolean(bool value)
    {
        return value ? L"true" : L"false";
    }

    uint64_t UnixSecondsNow()
    {
        FILETIME value = {};
        GetSystemTimeAsFileTime(&value);
        const uint64_t ticks = (static_cast<uint64_t>(value.dwHighDateTime) << 32) |
            value.dwLowDateTime;
        constexpr uint64_t epoch = 116444736000000000ULL;
        return ticks >= epoch ? (ticks - epoch) / 10000000ULL : 0;
    }

    bool Sha256(const uint8_t* bytes, size_t length, std::vector<uint8_t>* digest)
    {
        bool ok = false;
        AlgorithmOwner algorithm;
        do
        {
            if (digest == nullptr || length > (std::numeric_limits<ULONG>::max)() ||
                (length != 0 && bytes == nullptr))
            {
                break;
            }
            digest->clear();
            if (BCryptOpenAlgorithmProvider(&algorithm.Handle, BCRYPT_SHA256_ALGORITHM,
                nullptr, 0) < 0)
            {
                break;
            }
            std::vector<uint8_t> output(32);
            if (BCryptHash(algorithm.Handle, nullptr, 0, const_cast<PUCHAR>(bytes),
                static_cast<ULONG>(length), output.data(), static_cast<ULONG>(output.size())) < 0)
            {
                break;
            }
            *digest = std::move(output);
            ok = true;
        } while (false);
        return ok;
    }

    bool Sha256(const std::vector<uint8_t>& bytes, std::vector<uint8_t>* digest)
    {
        return Sha256(bytes.data(), bytes.size(), digest);
    }

    bool SameBytes(const std::vector<uint8_t>& left, const std::vector<uint8_t>& right)
    {
        if (left.size() != right.size())
        {
            return false;
        }
        uint8_t difference = 0;
        for (size_t index = 0; index < left.size(); ++index)
        {
            difference |= left[index] ^ right[index];
        }
        return difference == 0;
    }

    bool HasNonzeroByte(const std::vector<uint8_t>& value)
    {
        return std::any_of(value.begin(), value.end(), [](uint8_t byte)
        {
            return byte != 0;
        });
    }

    bool ValidDeviceIdentity(const std::string& identity)
    {
        return !identity.empty() && identity.size() <= 256 &&
            std::all_of(identity.begin(), identity.end(), [](unsigned char ch)
        {
            return ch >= 0x21 && ch <= 0x7e;
        });
    }

    void AppendU32(std::vector<uint8_t>* output, uint32_t value)
    {
        for (unsigned index = 0; index < 4; ++index)
        {
            output->push_back(static_cast<uint8_t>(value >> (index * 8)));
        }
    }

    void AppendU64(std::vector<uint8_t>* output, uint64_t value)
    {
        for (unsigned index = 0; index < 8; ++index)
        {
            output->push_back(static_cast<uint8_t>(value >> (index * 8)));
        }
    }

    void AppendBytes(std::vector<uint8_t>* output, const uint8_t* bytes, size_t size)
    {
        AppendU32(output, static_cast<uint32_t>(size));
        if (size != 0)
        {
            output->insert(output->end(), bytes, bytes + size);
        }
    }

    bool VerifyP256Signature(const std::vector<uint8_t>& publicBlob,
        const std::vector<uint8_t>& digest, const std::vector<uint8_t>& signature)
    {
        bool ok = false;
        AlgorithmOwner algorithm;
        KeyOwner key;
        do
        {
            if (publicBlob.size() != sizeof(BCRYPT_ECCKEY_BLOB) + 64 ||
                digest.size() != 32 || signature.size() != 64)
            {
                break;
            }
            BCRYPT_ECCKEY_BLOB header = {};
            memcpy(&header, publicBlob.data(), sizeof(header));
            if (header.dwMagic != BCRYPT_ECDSA_PUBLIC_P256_MAGIC || header.cbKey != 32 ||
                BCryptOpenAlgorithmProvider(&algorithm.Handle, BCRYPT_ECDSA_P256_ALGORITHM,
                    nullptr, 0) < 0 ||
                BCryptImportKeyPair(algorithm.Handle, nullptr, BCRYPT_ECCPUBLIC_BLOB,
                    &key.Handle, const_cast<PUCHAR>(publicBlob.data()),
                    static_cast<ULONG>(publicBlob.size()), 0) < 0)
            {
                break;
            }
            ok = BCryptVerifySignature(key.Handle, nullptr,
                const_cast<PUCHAR>(digest.data()), static_cast<ULONG>(digest.size()),
                const_cast<PUCHAR>(signature.data()), static_cast<ULONG>(signature.size()), 0) >= 0;
        } while (false);
        return ok;
    }

    struct JsonNode
    {
        wchar_t Type = 0;
        std::wstring Scalar;
        std::map<std::wstring, JsonNode> Members;
        std::vector<JsonNode> Items;
    };

    // This parser rejects duplicate keys and malformed values before any trust projection.
    class BoundedJsonParser
    {
    public:
        explicit BoundedJsonParser(const std::wstring& text) : text_(text)
        {
        }

        bool Parse(JsonNode* result)
        {
            bool ok = false;
            do
            {
                if (result == nullptr || text_.size() > kMaximumCiToolBytes)
                {
                    break;
                }
                SkipSpace();
                if (!Value(0, result))
                {
                    break;
                }
                SkipSpace();
                ok = position_ == text_.size();
            } while (false);
            return ok;
        }

    private:
        void SkipSpace()
        {
            while (position_ < text_.size() && (text_[position_] == L' ' ||
                text_[position_] == L'\r' || text_[position_] == L'\n' || text_[position_] == L'\t'))
            {
                ++position_;
            }
        }

        bool Take(wchar_t ch)
        {
            const bool matched = position_ < text_.size() && text_[position_] == ch;
            if (matched)
            {
                ++position_;
            }
            return matched;
        }

        bool HexUnit(wchar_t* unit)
        {
            unsigned value = 0;
            for (unsigned index = 0; index < 4; ++index)
            {
                if (position_ >= text_.size())
                {
                    return false;
                }
                const wchar_t ch = text_[position_++];
                unsigned digit = 16;
                if (ch >= L'0' && ch <= L'9')
                {
                    digit = ch - L'0';
                }
                else if (ch >= L'a' && ch <= L'f')
                {
                    digit = ch - L'a' + 10;
                }
                else if (ch >= L'A' && ch <= L'F')
                {
                    digit = ch - L'A' + 10;
                }
                if (digit > 15)
                {
                    return false;
                }
                value = (value << 4) | digit;
            }
            *unit = static_cast<wchar_t>(value);
            return true;
        }

        bool String(std::wstring* value)
        {
            if (!Take(L'"'))
            {
                return false;
            }
            value->clear();
            bool expectingLowSurrogate = false;
            while (position_ < text_.size())
            {
                wchar_t ch = text_[position_++];
                if (ch == L'"')
                {
                    return !expectingLowSurrogate;
                }
                if (ch < 0x20 || value->size() >= 16384)
                {
                    return false;
                }
                if (ch == L'\\')
                {
                    if (position_ >= text_.size())
                    {
                        return false;
                    }
                    const wchar_t escaped = text_[position_++];
                    switch (escaped)
                    {
                        case L'"':
                        case L'\\':
                        case L'/':
                        {
                            ch = escaped;
                            break;
                        }
                        case L'b':
                        {
                            ch = L'\b';
                            break;
                        }
                        case L'f':
                        {
                            ch = L'\f';
                            break;
                        }
                        case L'n':
                        {
                            ch = L'\n';
                            break;
                        }
                        case L'r':
                        {
                            ch = L'\r';
                            break;
                        }
                        case L't':
                        {
                            ch = L'\t';
                            break;
                        }
                        case L'u':
                        {
                            if (!HexUnit(&ch))
                            {
                                return false;
                            }
                            break;
                        }
                        default:
                        {
                            return false;
                        }
                    }
                }
                const bool low = ch >= 0xdc00 && ch <= 0xdfff;
                const bool high = ch >= 0xd800 && ch <= 0xdbff;
                if (expectingLowSurrogate != low)
                {
                    return false;
                }
                expectingLowSurrogate = high;
                value->push_back(ch);
            }
            return false;
        }

        bool Number(JsonNode* result)
        {
            const size_t start = position_;
            Take(L'-');
            if (!Take(L'0'))
            {
                if (position_ >= text_.size() || text_[position_] < L'1' || text_[position_] > L'9')
                {
                    return false;
                }
                while (position_ < text_.size() && text_[position_] >= L'0' && text_[position_] <= L'9')
                {
                    ++position_;
                }
            }
            if (Take(L'.'))
            {
                const size_t digits = position_;
                while (position_ < text_.size() && text_[position_] >= L'0' && text_[position_] <= L'9')
                {
                    ++position_;
                }
                if (position_ == digits)
                {
                    return false;
                }
            }
            if (Take(L'e') || Take(L'E'))
            {
                if (!Take(L'+'))
                {
                    Take(L'-');
                }
                const size_t digits = position_;
                while (position_ < text_.size() && text_[position_] >= L'0' && text_[position_] <= L'9')
                {
                    ++position_;
                }
                if (position_ == digits)
                {
                    return false;
                }
            }
            result->Type = L'n';
            result->Scalar = text_.substr(start, position_ - start);
            return result->Scalar.size() <= 128;
        }

        bool Value(unsigned depth, JsonNode* result)
        {
            if (depth > 16 || ++nodes_ > 32768 || position_ >= text_.size())
            {
                return false;
            }
            if (text_[position_] == L'"')
            {
                result->Type = L's';
                return String(&result->Scalar);
            }
            if (Take(L'{'))
            {
                result->Type = L'o';
                SkipSpace();
                if (Take(L'}'))
                {
                    return true;
                }
                do
                {
                    SkipSpace();
                    std::wstring key;
                    JsonNode member;
                    if (result->Members.size() >= 128 || !String(&key))
                    {
                        return false;
                    }
                    SkipSpace();
                    if (!Take(L':'))
                    {
                        return false;
                    }
                    SkipSpace();
                    if (!Value(depth + 1, &member) || !result->Members.emplace(key, std::move(member)).second)
                    {
                        return false;
                    }
                    SkipSpace();
                    if (Take(L'}'))
                    {
                        return true;
                    }
                } while (Take(L','));
                return false;
            }
            if (Take(L'['))
            {
                result->Type = L'a';
                SkipSpace();
                if (Take(L']'))
                {
                    return true;
                }
                do
                {
                    SkipSpace();
                    JsonNode item;
                    if (result->Items.size() >= 4096 || !Value(depth + 1, &item))
                    {
                        return false;
                    }
                    result->Items.push_back(std::move(item));
                    SkipSpace();
                    if (Take(L']'))
                    {
                        return true;
                    }
                } while (Take(L','));
                return false;
            }
            for (const auto* token : { L"true", L"false", L"null" })
            {
                const size_t length = wcslen(token);
                if (text_.compare(position_, length, token) == 0)
                {
                    result->Type = token[0] == L'n' ? L'z' : L'b';
                    result->Scalar = token;
                    position_ += length;
                    return true;
                }
            }
            return Number(result);
        }

        const std::wstring& text_;
        size_t position_ = 0;
        size_t nodes_ = 0;
    };

    const JsonNode* JsonMember(const JsonNode& object, const wchar_t* name)
    {
        const auto found = object.Members.find(name);
        return object.Type == L'o' && found != object.Members.end() ? &found->second : nullptr;
    }

    bool PolicyIdValid(const std::wstring& id)
    {
        const size_t offset = id.size() == 38 && id.front() == L'{' && id.back() == L'}' ? 1 : 0;
        if (id.size() != 36 + offset * 2)
        {
            return false;
        }
        for (size_t index = 0; index < 36; ++index)
        {
            const wchar_t ch = id[offset + index];
            if (index == 8 || index == 13 || index == 18 || index == 23)
            {
                if (ch != L'-')
                {
                    return false;
                }
            }
            else if (!((ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f') ||
                (ch >= L'A' && ch <= L'F')))
            {
                return false;
            }
        }
        return true;
    }

    std::wstring LowerAscii(std::wstring value)
    {
        for (wchar_t& ch : value)
        {
            if (ch >= L'A' && ch <= L'Z')
            {
                ch += L'a' - L'A';
            }
        }
        return value;
    }

    bool ParseCiToolPolicies(const std::wstring& json,
        std::map<std::wstring, std::wstring>* fields, std::wstring* reason)
    {
        bool ok = false;
        do
        {
            JsonNode root;
            BoundedJsonParser parser(json);
            if (!parser.Parse(&root))
            {
                *reason = L"CiTool output is malformed or exceeds parser limits";
                break;
            }
            const JsonNode* policies = JsonMember(root, L"Policies");
            if (policies == nullptr || policies->Type != L'a' || policies->Items.size() > kMaximumPolicies)
            {
                *reason = L"CiTool Policies array is unavailable or exceeds 512 rows";
                break;
            }
            bool complete = true;
            std::set<std::wstring> ids;
            (*fields)[L"citool.policy_count"] = std::to_wstring(policies->Items.size());
            for (size_t index = 0; index < policies->Items.size(); ++index)
            {
                const auto& policy = policies->Items[index];
                const std::wstring prefix = L"citool.policy." + std::to_wstring(index) + L".";
                const JsonNode* id = JsonMember(policy, L"PolicyID");
                const JsonNode* version = JsonMember(policy, L"Version");
                const JsonNode* enforced = JsonMember(policy, L"IsEnforced");
                if (id == nullptr || id->Type != L's' || !PolicyIdValid(id->Scalar))
                {
                    complete = false;
                    (*fields)[prefix + L"id"] = L"unknown";
                }
                else
                {
                    (*fields)[prefix + L"id"] = id->Scalar;
                    std::wstring canonicalId = LowerAscii(id->Scalar);
                    if (canonicalId.front() == L'{')
                    {
                        canonicalId = canonicalId.substr(1, 36);
                    }
                    if (!ids.insert(canonicalId).second)
                    {
                        complete = false;
                    }
                }
                if (version == nullptr || (version->Type != L'n' && version->Type != L's') ||
                    version->Scalar.empty() || version->Scalar.size() > 128)
                {
                    complete = false;
                    (*fields)[prefix + L"version_raw"] = L"unknown";
                }
                else
                {
                    (*fields)[prefix + L"version_raw"] = version->Scalar;
                }
                if (enforced == nullptr || (enforced->Type != L'b' && enforced->Type != L's') ||
                    (LowerAscii(enforced->Scalar) != L"true" && LowerAscii(enforced->Scalar) != L"false"))
                {
                    complete = false;
                    (*fields)[prefix + L"is_enforced_observed"] = L"unknown";
                }
                else
                {
                    (*fields)[prefix + L"is_enforced_raw"] = enforced->Scalar;
                    (*fields)[prefix + L"is_enforced_observed"] = LowerAscii(enforced->Scalar);
                }
                const JsonNode* name = JsonMember(policy, L"FriendlyName");
                if (name != nullptr && name->Type == L's')
                {
                    (*fields)[prefix + L"friendly_name"] = name->Scalar;
                }
                const JsonNode* base = JsonMember(policy, L"BasePolicyID");
                if (base != nullptr && base->Type == L's')
                {
                    (*fields)[prefix + L"base_policy_id_raw"] = base->Scalar;
                }
            }
            if (!complete)
            {
                *reason = L"CiTool policy metadata is missing, duplicated or unsupported";
                break;
            }
            ok = true;
        } while (false);
        return ok;
    }

    bool DecodeCiToolOutput(const std::vector<uint8_t>& bytes, std::wstring* text)
    {
        bool ok = false;
        do
        {
            text->clear();
            if (bytes.empty() || bytes.size() > kMaximumCiToolBytes)
            {
                break;
            }
            // CiTool versions can write UTF-16LE or UTF-8 when redirected.
            if ((bytes.size() >= 2 && bytes[0] == 0xff && bytes[1] == 0xfe) ||
                (bytes.size() >= 2 && bytes[1] == 0 && (bytes[0] == '{' || bytes[0] == ' ' ||
                    bytes[0] == '\r' || bytes[0] == '\n' || bytes[0] == '\t')))
            {
                const size_t skip = bytes[0] == 0xff ? 2 : 0;
                if ((bytes.size() - skip) % 2 != 0)
                {
                    break;
                }
                text->resize((bytes.size() - skip) / 2);
                for (size_t index = 0; index < text->size(); ++index)
                {
                    (*text)[index] = static_cast<wchar_t>(bytes[skip + index * 2] |
                        (static_cast<unsigned>(bytes[skip + index * 2 + 1]) << 8));
                }
                ok = true;
                break;
            }
            const size_t skip = bytes.size() >= 3 && bytes[0] == 0xef && bytes[1] == 0xbb && bytes[2] == 0xbf ? 3 : 0;
            const int length = static_cast<int>(bytes.size() - skip);
            const char* input = reinterpret_cast<const char*>(bytes.data() + skip);
            const int characters = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input, length, nullptr, 0);
            if (characters <= 0)
            {
                break;
            }
            text->resize(characters);
            ok = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input, length,
                text->data(), characters) == characters;
        } while (false);
        return ok;
    }

    bool RunCiTool(std::vector<uint8_t>* output, DWORD* exitCode, std::wstring* reason)
    {
        bool ok = false;
        OwnedHandle job;
        OwnedHandle process;
        ChildProcessCleanup childCleanup;
        OwnedHandle thread;
        OwnedHandle pipeRead;
        OwnedHandle pipeWrite;
        OwnedHandle input;
        AttributeListOwner attributes;
        const uint64_t started = GetTickCount64();
        do
        {
            output->clear();
            *exitCode = STILL_ACTIVE;
            wchar_t directory[MAX_PATH + 1] = {};
            const UINT directoryLength = GetSystemDirectoryW(directory, static_cast<UINT>(std::size(directory)));
            if (directoryLength == 0 || directoryLength >= std::size(directory))
            {
                *reason = L"GetSystemDirectoryW failed";
                break;
            }
            const std::wstring executable = std::wstring(directory) + L"\\CiTool.exe";
            const DWORD fileAttributes = GetFileAttributesW(executable.c_str());
            if (fileAttributes == INVALID_FILE_ATTRIBUTES || (fileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
            {
                *reason = L"CiTool is unavailable; policy enforcement is unknown";
                break;
            }
            SECURITY_ATTRIBUTES security = { sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE };
            HANDLE readHandle = nullptr;
            HANDLE writeHandle = nullptr;
            if (!CreatePipe(&readHandle, &writeHandle, &security, 0))
            {
                *reason = L"CiTool pipe creation failed";
                break;
            }
            pipeRead.Reset(readHandle);
            pipeWrite.Reset(writeHandle);
            if (!SetHandleInformation(pipeRead.Get(), HANDLE_FLAG_INHERIT, 0))
            {
                *reason = L"CiTool pipe inheritance setup failed";
                break;
            }
            input.Reset(CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                &security, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
            if (!input.Valid())
            {
                *reason = L"CiTool null input handle is unavailable";
                break;
            }
            SIZE_T attributeBytes = 0;
            InitializeProcThreadAttributeList(nullptr, 1, 0, &attributeBytes);
            if (attributeBytes == 0 || attributeBytes > 16384)
            {
                *reason = L"CiTool attribute list size is invalid";
                break;
            }
            attributes.Storage.resize(attributeBytes);
            auto* attributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributes.Storage.data());
            if (!InitializeProcThreadAttributeList(attributeList, 1, 0, &attributeBytes))
            {
                *reason = L"CiTool attribute list initialization failed";
                break;
            }
            attributes.List = attributeList;
            HANDLE inherited[] = { pipeWrite.Get(), input.Get() };
            if (!UpdateProcThreadAttribute(attributes.List, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                inherited, sizeof(inherited), nullptr, nullptr))
            {
                *reason = L"CiTool explicit handle inheritance setup failed";
                break;
            }
            job.Reset(CreateJobObjectW(nullptr, nullptr));
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {};
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if (!job.Valid() || !SetInformationJobObject(job.Get(), JobObjectExtendedLimitInformation,
                &limits, sizeof(limits)))
            {
                *reason = L"CiTool cleanup job setup failed";
                break;
            }
            STARTUPINFOEXW startup = {};
            startup.StartupInfo.cb = sizeof(startup);
            startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
            startup.StartupInfo.wShowWindow = SW_HIDE;
            startup.StartupInfo.hStdOutput = pipeWrite.Get();
            startup.StartupInfo.hStdError = pipeWrite.Get();
            startup.StartupInfo.hStdInput = input.Get();
            startup.lpAttributeList = attributes.List;
            PROCESS_INFORMATION child = {};
            std::wstring command = L"\"" + executable + L"\" --list-policies --json";
            if (!CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, TRUE,
                CREATE_NO_WINDOW | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, nullptr,
                directory, &startup.StartupInfo, &child))
            {
                *reason = L"CiTool process creation failed: " + HexNumber(GetLastError());
                break;
            }
            process.Reset(child.hProcess);
            childCleanup.Process = process.Get();
            thread.Reset(child.hThread);
            pipeWrite.Reset();
            if (!AssignProcessToJobObject(job.Get(), process.Get()) || ResumeThread(thread.Get()) == MAXDWORD)
            {
                *reason = L"CiTool process isolation or startup failed";
                break;
            }
            for (;;)
            {
                const uint64_t elapsed = GetTickCount64() - started;
                if (elapsed >= kCiToolTimeoutMs)
                {
                    *reason = L"CiTool query exceeded 3000 ms";
                    break;
                }
                DWORD available = 0;
                if (!PeekNamedPipe(pipeRead.Get(), nullptr, 0, nullptr, &available, nullptr))
                {
                    if (GetLastError() != ERROR_BROKEN_PIPE)
                    {
                        *reason = L"CiTool output pipe query failed";
                        break;
                    }
                    available = 0;
                }
                if (available != 0)
                {
                    if (output->size() >= kMaximumCiToolBytes)
                    {
                        *reason = L"CiTool output exceeds 256 KiB";
                        break;
                    }
                    uint8_t buffer[4096] = {};
                    const DWORD request = static_cast<DWORD>((std::min)({ sizeof(buffer),
                        static_cast<size_t>(available), kMaximumCiToolBytes - output->size() }));
                    DWORD received = 0;
                    if (!ReadFile(pipeRead.Get(), buffer, request, &received, nullptr) || received == 0)
                    {
                        *reason = L"CiTool output read failed";
                        break;
                    }
                    output->insert(output->end(), buffer, buffer + received);
                    continue;
                }
                const DWORD wait = WaitForSingleObject(process.Get(), static_cast<DWORD>((std::min)(
                    uint64_t(20), uint64_t(kCiToolTimeoutMs) - elapsed)));
                if (wait == WAIT_OBJECT_0)
                {
                    childCleanup.Exited = true;
                    // Recheck the pipe after observing process exit to drain its final write.
                    DWORD finalAvailable = 0;
                    if (PeekNamedPipe(pipeRead.Get(), nullptr, 0, nullptr, &finalAvailable, nullptr) &&
                        finalAvailable != 0)
                    {
                        continue;
                    }
                    if (!GetExitCodeProcess(process.Get(), exitCode) || *exitCode != ERROR_SUCCESS)
                    {
                        *reason = L"CiTool returned a nonzero or unavailable exit status";
                        break;
                    }
                    ok = true;
                    break;
                }
                if (wait == WAIT_FAILED)
                {
                    *reason = L"CiTool process wait failed";
                    break;
                }
            }
        } while (false);
        return ok;
    }

    bool CollectCodeIntegrity(KmonPlatformEvidenceResult* result)
    {
        using QueryFunction = NTSTATUS(NTAPI*)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
        const auto query = reinterpret_cast<QueryFunction>(GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
        result->Fields[L"ci.source"] = L"NtQuerySystemInformation(SystemCodeIntegrityInformation=103)";
        result->Fields[L"ci.state"] = L"unknown";
        if (query == nullptr)
        {
            result->Warnings.push_back(L"Code integrity query is unavailable");
            return false;
        }
        SYSTEM_CODEINTEGRITY_INFORMATION information = {};
        information.Length = sizeof(information);
        ULONG returned = 0;
        const NTSTATUS status = query(static_cast<SYSTEM_INFORMATION_CLASS>(103), &information,
            sizeof(information), &returned);
        result->Fields[L"ci.ntstatus"] = HexNumber(static_cast<uint32_t>(status));
        if (status < 0 || returned != sizeof(information) || information.Length != sizeof(information))
        {
            result->Warnings.push_back(L"Code integrity query did not return a complete known structure");
            return false;
        }
        const ULONG flags = information.CodeIntegrityOptions;
        result->Fields[L"ci.state"] = L"observed";
        result->Fields[L"ci.raw_mask"] = HexNumber(flags);
        result->Fields[L"ci.kmci_enabled_observed"] = Boolean((flags & CODEINTEGRITY_OPTION_ENABLED) != 0);
        result->Fields[L"ci.testsign_observed"] = Boolean((flags & CODEINTEGRITY_OPTION_TESTSIGN) != 0);
        result->Fields[L"ci.umci_enabled_observed"] = Boolean((flags & CODEINTEGRITY_OPTION_UMCI_ENABLED) != 0);
        result->Fields[L"ci.umci_audit_observed"] = Boolean((flags & CODEINTEGRITY_OPTION_UMCI_AUDITMODE_ENABLED) != 0);
        result->Fields[L"ci.hvci_kmci_enabled_observed"] = Boolean((flags & CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED) != 0);
        result->Fields[L"ci.hvci_kmci_audit_observed"] = Boolean((flags & CODEINTEGRITY_OPTION_HVCI_KMCI_AUDITMODE_ENABLED) != 0);
        result->Fields[L"ci.hvci_strict_observed"] = Boolean((flags & CODEINTEGRITY_OPTION_HVCI_KMCI_STRICTMODE_ENABLED) != 0);
        result->Fields[L"ci.hvci_ium_observed"] = Boolean((flags & CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED) != 0);
        result->Fields[L"ci.unknown_option_mask"] = HexNumber(flags & ~ULONG(0x3fff));
        return true;
    }

    bool CollectBlocklistConfiguration(KmonPlatformEvidenceResult* result)
    {
        result->Fields[L"blocklist.registry_semantics"] = L"configuration only; not enforcement evidence";
        result->Fields[L"blocklist.configuration_raw"] = L"unknown";
        DWORD type = 0;
        DWORD value = 0;
        DWORD bytes = sizeof(value);
        const LSTATUS status = RegGetValueW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\CI\\Config", L"VulnerableDriverBlocklistEnable",
            RRF_RT_REG_DWORD | RRF_SUBKEY_WOW6464KEY, &type, &value, &bytes);
        result->Fields[L"blocklist.registry_status"] = HexNumber(static_cast<uint32_t>(status));
        if (status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND)
        {
            result->Fields[L"blocklist.configuration_raw"] = L"absent; OS default not inferred";
            return true;
        }
        if (status != ERROR_SUCCESS || type != REG_DWORD || bytes != sizeof(value))
        {
            result->Warnings.push_back(L"Vulnerable driver blocklist configuration query failed");
            return false;
        }
        result->Fields[L"blocklist.configuration_raw"] = HexNumber(value);
        return true;
    }

    bool DecodeFirmwareRegistryString(DWORD type, const wchar_t* data, DWORD bytes,
        size_t capacity, std::wstring* value)
    {
        if (type != REG_SZ || data == nullptr || bytes < sizeof(wchar_t) ||
            bytes % sizeof(wchar_t) != 0 || bytes / sizeof(wchar_t) > capacity)
        {
            return false;
        }
        const size_t characters = bytes / sizeof(wchar_t);
        if (data[characters - 1] != L'\0')
        {
            return false;
        }
        const wchar_t* end = std::find(data, data + characters, L'\0');
        value->assign(data, end);
        return !value->empty();
    }

    bool CollectFirmwareInventory(KmonPlatformEvidenceResult* result)
    {
        result->Fields[L"firmware.source_trust"] = L"same-OS registry inventory; firmware authenticity not established";
        result->Fields[L"firmware.vendor_security_status_assessment"] = L"not configured";
        result->Fields[L"firmware.source"] = L"HKLM/HARDWARE/DESCRIPTION/System/BIOS";
        const std::pair<const wchar_t*, const wchar_t*> fields[] =
        {
            {L"BIOSVendor", L"firmware.bios_vendor"},
            {L"BIOSVersion", L"firmware.bios_version"},
            {L"BIOSReleaseDate", L"firmware.bios_release_date"},
            {L"BaseBoardManufacturer", L"firmware.baseboard_manufacturer"},
            {L"BaseBoardProduct", L"firmware.baseboard_product"}
        };
        bool complete = true;
        for (const auto& field : fields)
        {
            wchar_t buffer[1024] = {};
            DWORD bytes = sizeof(buffer);
            DWORD type = 0;
            const LSTATUS status = RegGetValueW(HKEY_LOCAL_MACHINE,
                L"HARDWARE\\DESCRIPTION\\System\\BIOS", field.first,
                RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY | RRF_ZEROONFAILURE,
                &type, buffer, &bytes);
            std::wstring value;
            const std::wstring key = field.second;
            result->Fields[key + L".status"] = HexNumber(static_cast<uint32_t>(status));
            if (status != ERROR_SUCCESS || !DecodeFirmwareRegistryString(type, buffer, bytes,
                std::size(buffer), &value))
            {
                complete = false;
                result->Fields[key] = L"unknown";
                result->Warnings.push_back(L"Firmware registry inventory unavailable: " + std::wstring(field.first));
            }
            else
            {
                result->Fields[key] = value;
            }
        }
        return complete;
    }

    bool CollectCiPolicies(KmonPlatformEvidenceResult* result)
    {
        result->Fields[L"citool.state"] = L"unknown";
        result->Fields[L"citool.source"] = L"SystemDirectory/CiTool.exe --list-policies --json";
        result->Fields[L"citool.timeout_ms"] = std::to_wstring(kCiToolTimeoutMs);
        std::vector<uint8_t> bytes;
        std::wstring reason;
        DWORD exitCode = STILL_ACTIVE;
        const bool ran = RunCiTool(&bytes, &exitCode, &reason);
        result->Fields[L"citool.exit_status"] = HexNumber(exitCode);
        result->Fields[L"citool.output_bytes"] = std::to_wstring(bytes.size());
        if (!ran)
        {
            result->Warnings.push_back(reason);
            return false;
        }
        std::wstring json;
        if (!DecodeCiToolOutput(bytes, &json))
        {
            result->Warnings.push_back(L"CiTool output encoding is unsupported or malformed");
            return false;
        }
        result->Fields[L"citool.raw_json"] = json;
        if (!ParseCiToolPolicies(json, &result->Fields, &reason))
        {
            result->Warnings.push_back(reason);
            return false;
        }
        result->Fields[L"citool.state"] = L"observed";
        return true;
    }

    bool CollectTpmEvidence(KmonPlatformEvidenceResult* result)
    {
        bool ok = false;
        TbsContextOwner context;
        result->Fields[L"tpm.device_state"] = L"unknown";
        result->Fields[L"tpm.boot_log_state"] = L"unknown";
        result->Fields[L"tpm.boot_log_is_quote"] = L"false";
        result->Fields[L"tpm.boot_log_semantics"] = L"local WBCL bytes; no PCR replay, AK certificate or quote validation";
        result->Fields[L"tpm.query_time_limit"] = L"TBS synchronous API has no caller-supplied timeout";
        do
        {
            TPM_DEVICE_INFO information = {};
            const TBS_RESULT deviceStatus = Tbsi_GetDeviceInfo(sizeof(information), &information);
            result->Fields[L"tpm.device_status"] = HexNumber(deviceStatus);
            if (deviceStatus != TBS_SUCCESS)
            {
                result->Warnings.push_back(L"TBS device information is unavailable");
                break;
            }
            result->Fields[L"tpm.struct_version_raw"] = std::to_wstring(information.structVersion);
            result->Fields[L"tpm.version_raw"] = std::to_wstring(information.tpmVersion);
            result->Fields[L"tpm.interface_raw"] = std::to_wstring(information.tpmInterfaceType);
            result->Fields[L"tpm.implementation_revision_raw"] = std::to_wstring(information.tpmImpRevision);
            if (information.structVersion != 1)
            {
                result->Warnings.push_back(L"TBS returned an unsupported device information version");
                break;
            }
            result->Fields[L"tpm.device_state"] = L"observed";
            TBS_CONTEXT_PARAMS2 parameters = {};
            parameters.version = TBS_CONTEXT_VERSION_TWO;
            parameters.includeTpm12 = 1;
            parameters.includeTpm20 = 1;
            const TBS_RESULT contextStatus = Tbsi_Context_Create(
                reinterpret_cast<PCTBS_CONTEXT_PARAMS>(&parameters), &context.Handle);
            result->Fields[L"tpm.context_status"] = HexNumber(contextStatus);
            if (contextStatus != TBS_SUCCESS)
            {
                result->Warnings.push_back(L"TBS log query context is unavailable");
                break;
            }
            std::vector<uint8_t> log;
            TBS_RESULT logStatus = static_cast<TBS_RESULT>(TBS_E_INTERNAL_ERROR);
            for (unsigned attempt = 0; attempt < 2; ++attempt)
            {
                UINT32 length = 0;
                logStatus = Tbsi_Get_TCG_Log(context.Handle, nullptr, &length);
                if (logStatus != TBS_SUCCESS || length == 0 || length > kMaximumBootLogBytes)
                {
                    break;
                }
                log.resize(length);
                UINT32 received = length;
                logStatus = Tbsi_Get_TCG_Log(context.Handle, log.data(), &received);
                if (logStatus == TBS_E_INSUFFICIENT_BUFFER)
                {
                    log.clear();
                    continue;
                }
                if (logStatus != TBS_SUCCESS || received == 0 || received > length)
                {
                    log.clear();
                    break;
                }
                log.resize(received);
                break;
            }
            result->Fields[L"tpm.boot_log_status"] = HexNumber(logStatus);
            std::vector<uint8_t> digest;
            if (logStatus != TBS_SUCCESS || log.empty() || !Sha256(log, &digest))
            {
                result->Warnings.push_back(L"TBS boot log is unavailable, changed or exceeds 4 MiB");
                break;
            }
            result->Fields[L"tpm.boot_log_bytes"] = std::to_wstring(log.size());
            result->Fields[L"tpm.boot_log_sha256"] = HexBytes(digest);
            result->Fields[L"tpm.boot_log_state"] = L"observed";
            ok = true;
        } while (false);
        return ok;
    }

    std::vector<uint8_t> FixtureHex(const char* hex)
    {
        std::vector<uint8_t> value;
        const size_t length = strlen(hex);
        if ((length & 1) != 0)
        {
            return value;
        }
        for (size_t index = 0; index < length; index += 2)
        {
            unsigned byte = 0;
            for (size_t part = 0; part < 2; ++part)
            {
                const char ch = hex[index + part];
                unsigned digit = 16;
                if (ch >= '0' && ch <= '9')
                {
                    digit = ch - '0';
                }
                else if (ch >= 'A' && ch <= 'F')
                {
                    digit = ch - 'A' + 10;
                }
                else if (ch >= 'a' && ch <= 'f')
                {
                    digit = ch - 'a' + 10;
                }
                if (digit > 15)
                {
                    return {};
                }
                byte = (byte << 4) | digit;
            }
            value.push_back(static_cast<uint8_t>(byte));
        }
        return value;
    }

    std::vector<uint8_t> FixturePublicKey()
    {
        // RFC 6979 A.2.5 public test key. It is never a production trust anchor.
        const auto coordinates = FixtureHex(
            "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6"
            "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299");
        const BCRYPT_ECCKEY_BLOB header = { BCRYPT_ECDSA_PUBLIC_P256_MAGIC, 32 };
        std::vector<uint8_t> blob(sizeof(header));
        memcpy(blob.data(), &header, sizeof(header));
        blob.insert(blob.end(), coordinates.begin(), coordinates.end());
        return blob;
    }

    bool SignFixtureClaim(KmonExternalAttestationClaim* claim)
    {
        bool ok = false;
        AlgorithmOwner algorithm;
        KeyOwner key;
        do
        {
            std::vector<uint8_t> payload;
            std::vector<uint8_t> digest;
            if (!BuildKmonAttestationClaimPayload(*claim, &payload) || !Sha256(payload, &digest))
            {
                break;
            }
            // Publicly documented RFC 6979 fixture private key; selftest only.
            auto privateBlob = FixturePublicKey();
            BCRYPT_ECCKEY_BLOB header = { BCRYPT_ECDSA_PRIVATE_P256_MAGIC, 32 };
            memcpy(privateBlob.data(), &header, sizeof(header));
            const auto secret = FixtureHex("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
            privateBlob.insert(privateBlob.end(), secret.begin(), secret.end());
            if (BCryptOpenAlgorithmProvider(&algorithm.Handle, BCRYPT_ECDSA_P256_ALGORITHM,
                nullptr, 0) < 0 ||
                BCryptImportKeyPair(algorithm.Handle, nullptr, BCRYPT_ECCPRIVATE_BLOB,
                    &key.Handle, privateBlob.data(), static_cast<ULONG>(privateBlob.size()), 0) < 0)
            {
                break;
            }
            claim->Signature.resize(64);
            ULONG written = 0;
            ok = BCryptSignHash(key.Handle, nullptr, digest.data(), static_cast<ULONG>(digest.size()),
                claim->Signature.data(), static_cast<ULONG>(claim->Signature.size()), &written, 0) >= 0 &&
                written == claim->Signature.size();
        } while (false);
        return ok;
    }
}

bool BuildKmonAttestationClaimPayload(const KmonExternalAttestationClaim& claim,
    std::vector<uint8_t>* payload)
{
    bool ok = false;
    do
    {
        if (payload == nullptr)
        {
            break;
        }
        payload->clear();
        if (!ValidDeviceIdentity(claim.DeviceIdentity) || claim.Nonce.size() != 32 ||
            !HasNonzeroByte(claim.Nonce) || claim.AttestationKeySha256.size() != 32 ||
            !HasNonzeroByte(claim.AttestationKeySha256) || claim.Quote.empty() ||
            claim.Quote.size() > kMaximumQuoteBytes)
        {
            break;
        }
        std::vector<uint8_t> quoteDigest;
        if (!Sha256(claim.Quote, &quoteDigest))
        {
            break;
        }
        static constexpr char domain[] = "KN-KMON-EXTERNAL-ATTESTATION";
        AppendBytes(payload, reinterpret_cast<const uint8_t*>(domain), sizeof(domain) - 1);
        AppendU32(payload, 1);
        AppendBytes(payload, reinterpret_cast<const uint8_t*>(claim.DeviceIdentity.data()),
            claim.DeviceIdentity.size());
        AppendBytes(payload, claim.AttestationKeySha256.data(), claim.AttestationKeySha256.size());
        AppendBytes(payload, claim.Nonce.data(), claim.Nonce.size());
        AppendBytes(payload, quoteDigest.data(), quoteDigest.size());
        AppendU64(payload, claim.IssuedUnixSeconds);
        AppendU64(payload, claim.ExpiresUnixSeconds);
        AppendU32(payload, claim.QuoteVerified ? 1 : 0);
        AppendU32(payload, claim.BootStateAccepted ? 1 : 0);
        ok = true;
    } while (false);
    return ok;
}

bool CreateKmonAttestationRequest(const std::string& deviceIdentity,
    const std::vector<uint8_t>& attestationKeySha256, KmonAttestationRequest* request,
    std::wstring* error)
{
    bool ok = false;
    if (error != nullptr)
    {
        error->clear();
    }
    do
    {
        if (request == nullptr)
        {
            break;
        }
        *request = {};
        if ((!deviceIdentity.empty() && !ValidDeviceIdentity(deviceIdentity)) ||
            (!attestationKeySha256.empty() && (attestationKeySha256.size() != 32 ||
                !HasNonzeroByte(attestationKeySha256))))
        {
            break;
        }
        KmonAttestationRequest candidate;
        candidate.Nonce.resize(32);
        candidate.DeviceIdentity = deviceIdentity;
        candidate.AttestationKeySha256 = attestationKeySha256;
        candidate.IssuedUnixSeconds = UnixSecondsNow();
        if (candidate.IssuedUnixSeconds == 0 ||
            candidate.IssuedUnixSeconds > UINT64_MAX - kRequestLifetimeSeconds ||
            BCryptGenRandom(nullptr, candidate.Nonce.data(), static_cast<ULONG>(candidate.Nonce.size()),
                BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0 || !HasNonzeroByte(candidate.Nonce))
        {
            break;
        }
        candidate.ExpiresUnixSeconds = candidate.IssuedUnixSeconds + kRequestLifetimeSeconds;
        *request = std::move(candidate);
        ok = true;
    } while (false);
    if (!ok && error != nullptr)
    {
        *error = L"Attestation nonce creation or expected identity validation failed";
    }
    return ok;
}

bool VerifyKmonExternalAttestation(KmonAttestationRequest* request,
    const KmonExternalAttestationClaim& claim,
    const std::vector<uint8_t>& trustedVerifierPublicKeyBlob, uint64_t nowUnixSeconds,
    KmonAttestationVerificationResult* result)
{
    bool trusted = false;
    do
    {
        if (result == nullptr)
        {
            break;
        }
        *result = {};
        result->Reason = L"external attestation is not trusted";
        if (request == nullptr || request->Consumed)
        {
            result->Reason = L"attestation request is missing or already consumed";
            break;
        }
        if (trustedVerifierPublicKeyBlob.empty() || !ValidDeviceIdentity(request->DeviceIdentity) ||
            request->AttestationKeySha256.size() != 32 || !HasNonzeroByte(request->AttestationKeySha256))
        {
            result->Reason = L"independently configured verifier, device identity and AK binding are required";
            break;
        }
        if (request->Nonce.size() != 32 || !HasNonzeroByte(request->Nonce) ||
            !SameBytes(request->Nonce, claim.Nonce) || request->DeviceIdentity != claim.DeviceIdentity ||
            !SameBytes(request->AttestationKeySha256, claim.AttestationKeySha256))
        {
            result->Reason = L"nonce, device identity or attestation key binding does not match";
            break;
        }
        if (request->IssuedUnixSeconds == 0 || request->ExpiresUnixSeconds <= request->IssuedUnixSeconds ||
            request->ExpiresUnixSeconds - request->IssuedUnixSeconds > kRequestLifetimeSeconds ||
            nowUnixSeconds < request->IssuedUnixSeconds || nowUnixSeconds >= request->ExpiresUnixSeconds ||
            claim.IssuedUnixSeconds < request->IssuedUnixSeconds || claim.IssuedUnixSeconds > nowUnixSeconds ||
            claim.ExpiresUnixSeconds <= claim.IssuedUnixSeconds || claim.ExpiresUnixSeconds > request->ExpiresUnixSeconds ||
            nowUnixSeconds >= claim.ExpiresUnixSeconds)
        {
            result->Reason = L"attestation freshness window is invalid or expired";
            break;
        }
        if (!claim.QuoteVerified || !claim.BootStateAccepted)
        {
            result->Reason = L"external verifier did not affirm quote validity and accepted boot state";
            break;
        }
        std::vector<uint8_t> payload;
        std::vector<uint8_t> digest;
        if (!BuildKmonAttestationClaimPayload(claim, &payload) || !Sha256(payload, &digest) ||
            !VerifyP256Signature(trustedVerifierPublicKeyBlob, digest, claim.Signature))
        {
            result->Reason = L"external verifier signature or claim format is invalid";
            break;
        }
        result->SignatureVerified = true;
        result->Trusted = true;
        result->Reason = L"configured verifier signed a fresh device-bound accepted quote verdict";
        request->Consumed = true;
        trusted = true;
    } while (false);
    return trusted;
}

bool CollectKmonPlatformEvidence(KmonPlatformEvidenceResult* result, std::wstring* error)
{
    if (error != nullptr)
    {
        error->clear();
    }
    if (result == nullptr)
    {
        if (error != nullptr)
        {
            *error = L"Platform evidence result pointer is null";
        }
        return false;
    }
    *result = {};
    result->Fields[L"evidence.source_trust"] = L"same-OS observations; not an independent root of trust";
    result->Fields[L"evidence.collection_unix_seconds"] = std::to_wstring(UnixSecondsNow());
    result->Fields[L"evidence.coverage_scope"] = L"local CI, configuration, firmware inventory, CiTool and TBS evidence";
    result->Fields[L"dma.preboot_absence_proven"] = L"false";
    result->Fields[L"dma.preboot_absence_reason"] = L"same-OS observations cannot establish preboot DMA absence";
    result->Fields[L"hypervisor.unauthorized_absence_proven"] = L"false";
    result->Fields[L"hypervisor.absence_reason"] = L"same-OS observations cannot exclude an untrusted lower execution layer";
    result->Fields[L"attestation.trusted"] = L"false";
    result->Fields[L"attestation.verifier_configured"] = L"false";
    result->Fields[L"attestation.device_ak_bound"] = L"false";
    result->Fields[L"attestation.quote_verified"] = L"false";
    result->Fields[L"attestation.reason"] = L"no configured external verifier, enrolled device AK or nonce-bound quote";
    const bool ci = CollectCodeIntegrity(result);
    const bool configuration = CollectBlocklistConfiguration(result);
    const bool firmware = CollectFirmwareInventory(result);
    const bool policies = CollectCiPolicies(result);
    const bool tpm = CollectTpmEvidence(result);
    KmonAttestationRequest request;
    std::wstring nonceError;
    const bool nonce = CreateKmonAttestationRequest({}, {}, &request, &nonceError);
    if (nonce)
    {
        result->Fields[L"attestation.request_nonce_hex"] = HexBytes(request.Nonce);
        result->Fields[L"attestation.request_issued_unix_seconds"] = std::to_wstring(request.IssuedUnixSeconds);
        result->Fields[L"attestation.request_expires_unix_seconds"] = std::to_wstring(request.ExpiresUnixSeconds);
        result->Fields[L"attestation.request_state"] = L"nonce_only; device identity and AK enrollment required";
    }
    else
    {
        result->Warnings.push_back(nonceError);
        result->Fields[L"attestation.request_state"] = L"unavailable";
    }
    result->Complete = ci && configuration && firmware && policies && tpm && nonce;
    result->Fields[L"evidence.local_collection_complete"] = Boolean(result->Complete);
    if (!result->Complete && error != nullptr)
    {
        *error = L"Some local platform evidence sources are unavailable or incomplete";
    }
    return true;
}

bool KmonPlatformEvidenceSelfTest()
{
    bool ok = false;
    do
    {
        const wchar_t registryFixture[] = L"Example Firmware";
        std::wstring registryValue;
        if (!DecodeFirmwareRegistryString(REG_SZ, registryFixture, sizeof(registryFixture),
                std::size(registryFixture), &registryValue) || registryValue != registryFixture ||
            DecodeFirmwareRegistryString(REG_BINARY, registryFixture, sizeof(registryFixture),
                std::size(registryFixture), &registryValue) ||
            DecodeFirmwareRegistryString(REG_SZ, registryFixture, sizeof(registryFixture) - 1,
                std::size(registryFixture), &registryValue) ||
            DecodeFirmwareRegistryString(REG_SZ, registryFixture, sizeof(registryFixture), 2, &registryValue) ||
            DecodeFirmwareRegistryString(REG_SZ, registryFixture, sizeof(registryFixture) - sizeof(wchar_t),
                std::size(registryFixture), &registryValue))
        {
            break;
        }
        const std::wstring policy =
            L"{\"Policies\":[{\"PolicyID\":\"d2bda982-ccf6-4344-ac5b-0b44427b6816\","
            L"\"Version\":2814751463178240,\"IsEnforced\":true}]}";
        std::map<std::wstring, std::wstring> fields;
        std::wstring reason;
        if (!ParseCiToolPolicies(policy, &fields, &reason) ||
            fields[L"citool.policy.0.version_raw"] != L"2814751463178240" ||
            fields[L"citool.policy.0.is_enforced_observed"] != L"true")
        {
            break;
        }
        fields.clear();
        if (!ParseCiToolPolicies(L"{\"Policies\":[]}", &fields, &reason) ||
            fields[L"citool.policy_count"] != L"0")
        {
            break;
        }
        for (const auto* invalid :
            {
                L"{\"Policies\":[],\"Policies\":[]}",
                L"{\"Policies\":[]} trailing",
                L"{\"Policies\":[{\"PolicyID\":\"bad\",\"Version\":1,\"IsEnforced\":true}]}",
                L"{\"Policies\":[{\"PolicyID\":\"d2bda982-ccf6-4344-ac5b-0b44427b6816\",\"Version\":1,\"IsEnforced\":1}]}",
                L"{\"Policies\":[{\"x\":\"\\uD800\"}]}",
                L"{\"Policies\":[,]}",
                L"{\"Policies\":[],\"x\":01}",
                L"{\"Policies\":[],\"x\":truefalse}"
            })
        {
            fields.clear();
            if (ParseCiToolPolicies(invalid, &fields, &reason))
            {
                return false;
            }
        }
        const std::wstring stringBoolean =
            L"{\"Policies\":[{\"PolicyID\":\"d2bda982-ccf6-4344-ac5b-0b44427b6816\","
            L"\"Version\":\"1.0.0.0\",\"IsEnforced\":\"False\"}]}";
        fields.clear();
        if (!ParseCiToolPolicies(stringBoolean, &fields, &reason) ||
            fields[L"citool.policy.0.is_enforced_observed"] != L"false")
        {
            break;
        }
        const std::wstring row =
            L"{\"PolicyID\":\"d2bda982-ccf6-4344-ac5b-0b44427b6816\",\"Version\":1,\"IsEnforced\":true}";
        fields.clear();
        if (ParseCiToolPolicies(L"{\"Policies\":[" + row + L"," + row + L"]}", &fields, &reason))
        {
            break;
        }
        std::wstring excessPolicies = L"{\"Policies\":[";
        for (size_t index = 0; index <= kMaximumPolicies; ++index)
        {
            if (index != 0)
            {
                excessPolicies += L",";
            }
            excessPolicies += row;
        }
        excessPolicies += L"]}";
        fields.clear();
        if (ParseCiToolPolicies(excessPolicies, &fields, &reason))
        {
            break;
        }
        const std::wstring utf16Source = L"\r\n{\"Policies\":[]}";
        std::vector<uint8_t> utf16;
        for (const wchar_t ch : utf16Source)
        {
            utf16.push_back(static_cast<uint8_t>(ch));
            utf16.push_back(static_cast<uint8_t>(ch >> 8));
        }
        std::wstring decoded;
        if (!DecodeCiToolOutput(utf16, &decoded) || decoded != utf16Source ||
            DecodeCiToolOutput({ 0xf0, 0x80, 0x80 }, &decoded))
        {
            break;
        }
        utf16.push_back(0);
        if (DecodeCiToolOutput(utf16, &decoded))
        {
            break;
        }
        const auto publicKey = FixturePublicKey();
        const std::vector<uint8_t> sample = { 's', 'a', 'm', 'p', 'l', 'e' };
        const auto knownSignature = FixtureHex(
            "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716"
            "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8");
        std::vector<uint8_t> digest;
        if (!Sha256(sample, &digest) || !VerifyP256Signature(publicKey, digest, knownSignature))
        {
            break;
        }
        digest[0] ^= 1;
        if (VerifyP256Signature(publicKey, digest, knownSignature))
        {
            break;
        }
        KmonAttestationRequest request;
        request.Nonce.assign(32, 0x31);
        request.DeviceIdentity = "fixture-device-1";
        request.AttestationKeySha256.assign(32, 0x42);
        request.IssuedUnixSeconds = 1000;
        request.ExpiresUnixSeconds = 1120;
        KmonExternalAttestationClaim claim;
        claim.Nonce = request.Nonce;
        claim.DeviceIdentity = request.DeviceIdentity;
        claim.AttestationKeySha256 = request.AttestationKeySha256;
        // Opaque fixture quote tests the verifier contract, not TPM quote decoding.
        claim.Quote = { 0x51, 0x55, 0x4f, 0x54, 0x45 };
        claim.IssuedUnixSeconds = 1001;
        claim.ExpiresUnixSeconds = 1110;
        claim.QuoteVerified = true;
        claim.BootStateAccepted = true;
        if (!SignFixtureClaim(&claim))
        {
            break;
        }
        KmonAttestationVerificationResult verified;
        auto positiveRequest = request;
        if (!VerifyKmonExternalAttestation(&positiveRequest, claim, publicKey, 1050, &verified) ||
            !verified.Trusted || !verified.SignatureVerified || verified.QuoteVerifiedLocally ||
            !positiveRequest.Consumed ||
            VerifyKmonExternalAttestation(&positiveRequest, claim, publicKey, 1050, &verified))
        {
            break;
        }
        for (unsigned mutation = 0; mutation < 16; ++mutation)
        {
            auto negativeRequest = request;
            auto negativeClaim = claim;
            auto negativeKey = publicKey;
            uint64_t now = 1050;
            switch (mutation)
            {
                case 0:
                {
                    negativeClaim.Nonce[0] ^= 1;
                    break;
                }
                case 1:
                {
                    negativeClaim.DeviceIdentity = "fixture-device-2";
                    break;
                }
                case 2:
                {
                    negativeClaim.AttestationKeySha256[0] ^= 1;
                    break;
                }
                case 3:
                {
                    now = 1110;
                    break;
                }
                case 4:
                {
                    negativeClaim.Quote[0] ^= 1;
                    break;
                }
                case 5:
                {
                    negativeClaim.Signature[0] ^= 1;
                    break;
                }
                case 6:
                {
                    negativeKey.clear();
                    break;
                }
                case 7:
                {
                    negativeRequest.AttestationKeySha256.clear();
                    break;
                }
                case 8:
                {
                    negativeClaim.QuoteVerified = false;
                    break;
                }
                case 9:
                {
                    negativeClaim.BootStateAccepted = false;
                    break;
                }
                case 10:
                {
                    now = 999;
                    break;
                }
                case 11:
                {
                    negativeClaim.Quote.clear();
                    break;
                }
                case 12:
                {
                    negativeClaim.ExpiresUnixSeconds = 1121;
                    break;
                }
                case 13:
                {
                    negativeClaim.IssuedUnixSeconds = 1051;
                    break;
                }
                case 14:
                {
                    negativeClaim.Quote.resize(kMaximumQuoteBytes + 1);
                    break;
                }
                default:
                {
                    negativeKey[8] ^= 1;
                    break;
                }
            }
            if (VerifyKmonExternalAttestation(&negativeRequest, negativeClaim, negativeKey, now, &verified) ||
                verified.Trusted || negativeRequest.Consumed)
            {
                return false;
            }
        }
        ok = true;
    } while (false);
    return ok;
}
