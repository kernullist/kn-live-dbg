#pragma once

#include <Windows.h>
#include <evntprov.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

// One opt-in marker joins the original native recipe to its QPC read intervals in a saved ETL.
namespace image_loader
{
    inline constexpr GUID Provider{0x02a921c3, 0x281c, 0x47c3, {0xa7, 0x34, 0x9b, 0x23, 0x3a, 0x73, 0x7d, 0x8d}};
    inline constexpr EVENT_DESCRIPTOR Completed{1, 1, 0, 4, 0, 0, 1};
    struct Interval { int64_t Start = 0, End = 0; };
    struct Window
    {
        std::array<char, 64> Recipe{};
        int64_t Frequency = 0;
        Interval Capture;
        std::array<Interval, 64> Reads{};
    };
    static_assert(offsetof(Window, Reads) == 88 && sizeof(Interval) == 16);

    inline int64_t Counter()
    {
        LARGE_INTEGER now{};
        return QueryPerformanceCounter(&now) ? now.QuadPart : 0;
    }

    class Registration
    {
        REGHANDLE Handle = 0;
    public:
        Registration() = default;
        Registration(const Registration&) = delete;
        Registration& operator=(const Registration&) = delete;
        ~Registration() { if (Handle) { EventUnregister(Handle); } }
        ULONG Open(Window& window)
        {
            LARGE_INTEGER frequency{};
            if (!QueryPerformanceFrequency(&frequency) || frequency.QuadPart <= 0) { return ERROR_NOT_SUPPORTED; }
            window.Frequency = frequency.QuadPart;
            const auto error = EventRegister(&Provider, nullptr, nullptr, &Handle);
            if (error != ERROR_SUCCESS) { return error; }
            return EventEnabled(Handle, &Completed) ? ERROR_SUCCESS : ERROR_NOT_READY;
        }
        ULONG Publish(Window& window, const std::wstring& digest, size_t count) const
        {
            if (!count || count > window.Reads.size() || digest.size() != window.Recipe.size() ||
                digest.find_first_not_of(L"0123456789abcdef") != std::wstring::npos ||
                window.Capture.Start <= 0 || window.Capture.End < window.Capture.Start)
                { return ERROR_INVALID_DATA; }
            if (!EventEnabled(Handle, &Completed)) { return ERROR_NOT_READY; }
            for (size_t i = 0; i < digest.size(); ++i) { window.Recipe[i] = static_cast<char>(digest[i]); }
            EVENT_DATA_DESCRIPTOR data{};
            EventDataDescCreate(&data, &window, static_cast<ULONG>(offsetof(Window, Reads) + count * sizeof(Interval)));
            return EventWrite(Handle, &Completed, 1, &data);
        }
    };
}
