#pragma once

#include <cstdint>
#include <cstddef>
#include <set>
#include <vector>

struct ScannerListCursor
{
    uint64_t Head = 0;
    uint64_t Entry = 0;
    uint64_t Forward = 0;
    uint64_t Backward = 0;
};

struct ScannerListNode
{
    uint64_t Address = 0;
    uint64_t Forward = 0;
    uint64_t Backward = 0;
};

struct ScannerListWindow
{
    std::vector<ScannerListNode> Nodes;
    ScannerListCursor Next;
    ScannerListCursor Anchor;
    uint64_t Head = 0;
    uint64_t TailSlot = 0;
    uint64_t First = 0;
    uint64_t Last = 0;
    size_t NodesVisited = 0;
    bool SinglyLinked = false;
    bool Restarted = false;
    bool ReachedEnd = false;
    bool Complete = false;
};

inline bool ScannerListPointer(uint64_t address)
{
    return address >= 0xffff800000000000ull && address <= ~0ull - 16 && (address & 7) == 0;
}

// Equal observations validate this window, not object lifetime or root membership
// under an undetected interior splice/ABA. Callers must validate object ownership.
template<typename Reader>
bool ValidateScannerListWindow(Reader& read, const ScannerListWindow& window)
{
    uint64_t first = 0;
    uint64_t last = 0;
    if (!read(window.Head, &first) || !read(window.TailSlot, &last) ||
        first != window.First || last != window.Last)
    {
        return false;
    }
    if (window.Anchor.Entry != 0)
    {
        uint64_t next = 0;
        uint64_t back = 0;
        if (!read(window.Anchor.Entry, &next) || next != window.Anchor.Forward ||
            (!window.SinglyLinked && (!read(window.Anchor.Entry + 8, &back) || back != window.Anchor.Backward)))
        {
            return false;
        }
    }
    for (const ScannerListNode& node : window.Nodes)
    {
        uint64_t next = 0;
        uint64_t back = 0;
        if (!read(node.Address, &next) || next != node.Forward ||
            (!window.SinglyLinked && (!read(node.Address + 8, &back) || back != node.Backward)))
        {
            return false;
        }
        if (!window.SinglyLinked)
        {
            uint64_t nextBack = 0;
            if (!read(next + 8, &nextBack) || nextBack != node.Address)
            {
                return false;
            }
        }
    }
    return true;
}

template<typename Reader>
bool ReadScannerListWindow(Reader& read, uint64_t head, uint64_t tailSlot, bool singlyLinked,
    size_t limit, const ScannerListCursor& cursor, ScannerListWindow* window)
{
    *window = {};
    window->Head = head;
    window->TailSlot = tailSlot;
    window->SinglyLinked = singlyLinked;
    if (!ScannerListPointer(head) || !ScannerListPointer(tailSlot & ~7ull) || limit == 0 || limit > 4096 ||
        !read(head, &window->First) || !read(tailSlot, &window->Last))
    {
        return false;
    }
    const uint64_t terminator = singlyLinked ? 0 : head;
    uint64_t current = window->First;
    uint64_t previous = head;
    if (cursor.Entry != 0)
    {
        uint64_t next = 0;
        uint64_t back = 0;
        const bool valid = cursor.Head == head && cursor.Entry != head && ScannerListPointer(cursor.Entry) &&
            read(cursor.Entry, &next) && next == cursor.Forward &&
            (singlyLinked || (read(cursor.Entry + 8, &back) && back == cursor.Backward &&
                ScannerListPointer(back) && read(back, &previous) && previous == cursor.Entry));
        if (valid)
        {
            window->Anchor = cursor;
            current = next;
            previous = cursor.Entry;
        }
        else
        {
            window->Restarted = true;
            previous = head;
        }
    }
    std::set<uint64_t> visited;
    if (window->Anchor.Entry != 0)
    {
        visited.insert(window->Anchor.Entry);
    }
    while (current != terminator && window->Nodes.size() < limit)
    {
        ++window->NodesVisited;
        ScannerListNode node;
        node.Address = current;
        if (!ScannerListPointer(current) || current == head || !visited.insert(current).second ||
            !read(current, &node.Forward) ||
            (!singlyLinked && (!read(current + 8, &node.Backward) || node.Backward != previous)) ||
            (node.Forward != terminator && !ScannerListPointer(node.Forward)))
        {
            window->Nodes.clear();
            return false;
        }
        window->Nodes.push_back(node);
        previous = current;
        current = node.Forward;
    }
    window->ReachedEnd = current == terminator;
    if ((!window->ReachedEnd && visited.find(current) != visited.end()) ||
        (window->ReachedEnd && previous != window->Last) || !ValidateScannerListWindow(read, *window))
    {
        window->Nodes.clear();
        return false;
    }
    window->Complete = window->ReachedEnd && window->Anchor.Entry == 0 && !window->Restarted;
    if (!window->ReachedEnd && !window->Nodes.empty())
    {
        const auto& last = window->Nodes.back();
        window->Next = {head, last.Address, last.Forward, last.Backward};
    }
    return true;
}

template<typename Reader, typename Writer>
bool ScannerListWindowFixture(Reader& read, Writer& write, uint64_t head)
{
    const uint64_t a = head + 0x100;
    const uint64_t b = head + 0x200;
    const uint64_t c = head + 0x300;
    write(head, a);
    write(head + 8, c);
    write(a, b);
    write(a + 8, head);
    write(b, c);
    write(b + 8, a);
    write(c, head);
    write(c + 8, b);
    ScannerListWindow first;
    ScannerListWindow second;
    if (!ReadScannerListWindow(read, head, head + 8, false, 2, {}, &first) || first.Complete ||
        first.ReachedEnd || first.Nodes.size() != 2 || first.Next.Entry != b ||
        !ReadScannerListWindow(read, head, head + 8, false, 2, first.Next, &second) ||
        !second.ReachedEnd || second.Complete || second.Nodes.size() != 1 || second.Nodes.front().Address != c ||
        !ReadScannerListWindow(read, head, head + 8, false, 3, second.Next, &second) || !second.Complete)
    {
        return false;
    }
    write(b, b);
    write(b + 8, b);
    write(a, c);
    write(c + 8, a);
    if (!ReadScannerListWindow(read, head, head + 8, false, 3, first.Next, &second) ||
        !second.Restarted || second.Nodes.size() != 2)
    {
        return false;
    }
    // A cursor whose links now belong to another root must restart.
    const uint64_t other = head + 0x1000;
    write(other, b);
    write(other + 8, b);
    write(b, other);
    write(b + 8, other);
    if (!ReadScannerListWindow(read, head, head + 8, false, 3, first.Next, &second) || !second.Restarted)
    {
        return false;
    }
    write(head, c);
    if (ValidateScannerListWindow(read, second))
    {
        return false;
    }
    write(head, a);
    write(head + 8, a);
    write(a, a);
    if (ReadScannerListWindow(read, head, head + 8, true, 3, {}, &second))
    {
        return false;
    }
    write(a, 0);
    return ReadScannerListWindow(read, head, head + 8, true, 1, {}, &second) && second.Complete;
}
