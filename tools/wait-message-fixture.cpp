// Observe a message sent between two threads of this process.
#include <windows.h>
#include <functional>
#include <iostream>
#include <string>
#include <thread>

namespace
{
    constexpr UINT Message = WM_APP + 1;
    constexpr LRESULT Answer = 71, EarlyAnswer = 83;
    constexpr DWORD DeadlineMs = 20000;
    enum class Mode { Send, Posted, Replied, Mixed, Timeout };

    struct Handle
    {
        HANDLE value;
        ~Handle() { if (value) { CloseHandle(value); } }
    };

    struct Fixture
    {
        Mode mode = Mode::Send;
        Handle ready{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
        Handle entered{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
        Handle returned{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
        Handle finish{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
        Handle mutex{CreateMutexW(nullptr, FALSE, nullptr)};
        HWND window = nullptr;
        DWORD handlerTid = 0, entryFlags = 0, flagsAfterReply = 0, replyOk = 0;
        DWORD firstMutexWait = WAIT_FAILED, sendError = ERROR_SUCCESS;
        ULONGLONG entryTick = 0, leaveTick = 0, sendBegin = 0, sendEnd = 0;
        bool handled = false, sent = false;
        DWORD_PTR result = 0;
    };

    LRESULT CALLBACK Procedure(HWND window, UINT message, WPARAM wp, LPARAM lp)
    {
        if (message == WM_NCCREATE)
        {
            const auto create = reinterpret_cast<CREATESTRUCTW*>(lp);
            SetLastError(ERROR_SUCCESS);
            if (!SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(create->lpCreateParams)) &&
                GetLastError() != ERROR_SUCCESS) { return FALSE; }
        }
        if (message != Message) { return DefWindowProcW(window, message, wp, lp); }
        auto& f = *reinterpret_cast<Fixture*>(GetWindowLongPtrW(window, GWLP_USERDATA));
        f.entryTick = GetTickCount64();
        f.handlerTid = GetCurrentThreadId();
        f.entryFlags = InSendMessageEx(nullptr);
        if (f.mode == Mode::Replied) { f.replyOk = ReplyMessage(EarlyAnswer); }
        f.flagsAfterReply = InSendMessageEx(nullptr);
        if (f.mode == Mode::Mixed)
        {
            f.firstMutexWait = WaitForSingleObject(f.mutex.value, 0);
            if (f.firstMutexWait == WAIT_OBJECT_0) { ReleaseMutex(f.mutex.value); }
        }
        SetEvent(f.entered.value);
        if (f.mode == Mode::Mixed)
        {
            const auto start = GetTickCount64();
            while (GetTickCount64() - start < DeadlineMs && WaitForSingleObject(f.finish.value, 0) == WAIT_TIMEOUT)
            {
                const auto wait = WaitForSingleObject(f.mutex.value, 500);
                if (wait == WAIT_TIMEOUT) { continue; }
                if (wait == WAIT_OBJECT_0) { ReleaseMutex(f.mutex.value); }
                return 0;
            }
        }
        f.handled = WaitForSingleObject(f.finish.value, DeadlineMs) == WAIT_OBJECT_0;
        f.leaveTick = GetTickCount64();
        return f.handled ? Answer : 0;
    }

    void Receive(Fixture& f)
    {
        WNDCLASSW wc{};
        wc.hInstance = GetModuleHandleW(nullptr);
        wc.lpfnWndProc = Procedure;
        wc.lpszClassName = L"KnWaitMessageFixture";
        const auto atom = RegisterClassW(&wc);
        if (atom)
        {
            f.window = CreateWindowExW(0, wc.lpszClassName, L"", 0, 0, 0, 0, 0,
                HWND_MESSAGE, nullptr, wc.hInstance, &f);
        }
        SetEvent(f.ready.value);
        if (f.window)
        {
            MSG msg{};
            while (MsgWaitForMultipleObjects(1, &f.finish.value, FALSE, DeadlineMs, QS_ALLINPUT) == WAIT_OBJECT_0 + 1)
            {
                while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) { DispatchMessageW(&msg); }
            }
            DestroyWindow(f.window);
        }
        if (atom) { UnregisterClassW(wc.lpszClassName, wc.hInstance); }
    }

    void Send(Fixture& f)
    {
        if (f.mode == Mode::Mixed && WaitForSingleObject(f.mutex.value, 1000) != WAIT_OBJECT_0) { return; }
        f.sendBegin = GetTickCount64();
        SetLastError(ERROR_SUCCESS);
        if (f.mode == Mode::Posted) { f.sent = PostMessageW(f.window, Message, 0, 0) != FALSE; }
        else
        {
            f.sent = SendMessageTimeoutW(f.window, Message, 0, 0, SMTO_BLOCK,
                f.mode == Mode::Timeout ? 6000 : DeadlineMs, &f.result) != 0;
        }
        if (!f.sent) { f.sendError = GetLastError(); }
        f.sendEnd = GetTickCount64();
        if (f.mode == Mode::Mixed) { ReleaseMutex(f.mutex.value); }
        SetEvent(f.returned.value);
        WaitForSingleObject(f.finish.value, DeadlineMs);
    }

    ULONGLONG Created(HANDLE h, bool thread)
    {
        FILETIME created{}, exit{}, kernel{}, user{};
        if (!(thread ? GetThreadTimes(h, &created, &exit, &kernel, &user) :
            GetProcessTimes(h, &created, &exit, &kernel, &user))) { return 0; }
        return (static_cast<ULONGLONG>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
    }

    bool WaitForRelease()
    {
        const auto input = GetStdHandle(STD_INPUT_HANDLE);
        const auto start = GetTickCount64();
        while (GetTickCount64() - start < DeadlineMs)
        {
            DWORD available = 0;
            if (!PeekNamedPipe(input, nullptr, 0, nullptr, &available, nullptr)) { return false; }
            if (available)
            {
                char ch = 0;
                DWORD read = 0;
                return ReadFile(input, &ch, 1, &read, nullptr) && read == 1 && ch == 'R';
            }
            Sleep(10);
        }
        return false;
    }
}

int main(int argc, char** argv)
{
    if (argc != 2) { return 2; }
    Fixture f;
    const std::string mode = argv[1];
    if (mode == "posted") { f.mode = Mode::Posted; }
    else if (mode == "replied") { f.mode = Mode::Replied; }
    else if (mode == "mixed") { f.mode = Mode::Mixed; }
    else if (mode == "timeout") { f.mode = Mode::Timeout; }
    else if (mode != "send") { return 2; }
    if (!f.ready.value || !f.entered.value || !f.returned.value || !f.finish.value || !f.mutex.value) { return 1; }
    std::thread receiver(Receive, std::ref(f));
    if (WaitForSingleObject(f.ready.value, DeadlineMs) != WAIT_OBJECT_0 || !f.window)
    { SetEvent(f.finish.value); receiver.join(); return 1; }
    std::thread sender(Send, std::ref(f));
    const bool expectReturned = f.mode == Mode::Posted || f.mode == Mode::Replied;
    const auto entered = WaitForSingleObject(f.entered.value, DeadlineMs);
    const auto returned = WaitForSingleObject(f.returned.value, expectReturned ? DeadlineMs : 0);
    bool observed = entered == WAIT_OBJECT_0 && returned == (expectReturned ? WAIT_OBJECT_0 : WAIT_TIMEOUT);
    if (observed)
    {
        std::cout << "{\"schema\":\"kn.wait_message_fixture.v1\",\"phase\":\"ready\",\"mode\":\"" << mode
            << "\",\"pid\":" << GetCurrentProcessId()
            << ",\"process_created\":\"" << Created(GetCurrentProcess(), false)
            << "\",\"sender_tid\":" << GetThreadId(sender.native_handle()) << ",\"sender_created\":\"" << Created(sender.native_handle(), true)
            << "\",\"receiver_tid\":" << GetThreadId(receiver.native_handle()) << ",\"receiver_created\":\"" << Created(receiver.native_handle(), true)
            << "\",\"handler_tid\":" << f.handlerTid << ",\"entry_flags\":" << f.entryFlags
            << ",\"reply_ok\":" << (f.mode == Mode::Replied ? std::to_string(f.replyOk) : "null")
            << ",\"after_flags\":" << f.flagsAfterReply << ",\"mutex_wait\":" << (f.mode == Mode::Mixed ? std::to_string(f.firstMutexWait) : "null")
            << ",\"sender_wait\":" << returned << "}" << std::endl;
        if (f.mode == Mode::Timeout)
        {
            observed = WaitForSingleObject(f.returned.value, DeadlineMs) == WAIT_OBJECT_0;
            if (observed)
            {
                std::cout << "{\"schema\":\"kn.wait_message_fixture.v1\",\"phase\":\"sender_returned\",\"send_ok\":"
                    << f.sent << ",\"send_error\":" << f.sendError << ",\"send_return_tick\":" << f.sendEnd << "}" << std::endl;
            }
        }
        observed = observed && WaitForRelease();
    }
    SetEvent(f.finish.value);
    sender.join();
    receiver.join();
    std::cout << "{\"schema\":\"kn.wait_message_fixture.v1\",\"phase\":\"completed\",\"mode\":\"" << mode
        << "\",\"send_ok\":" << f.sent << ",\"send_error\":" << (f.sent ? "null" : std::to_string(f.sendError))
        << ",\"result\":" << (f.sent && f.mode != Mode::Posted ? std::to_string(f.result) : "null")
        << ",\"handled\":" << f.handled << ",\"send_begin_tick\":" << f.sendBegin
        << ",\"send_return_tick\":" << f.sendEnd << ",\"handler_entry_tick\":" << f.entryTick
        << ",\"handler_leave_tick\":" << f.leaveTick << "}" << std::endl;
    return observed && f.sent == (f.mode != Mode::Timeout) && f.handled ? 0 : 1;
}
