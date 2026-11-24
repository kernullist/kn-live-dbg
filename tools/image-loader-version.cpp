// Two revisions of the same benign DLL exercise address reuse in the owned loader trial.
extern "C" __declspec(dllexport) unsigned FixtureChecksum(unsigned seed)
{
    unsigned value = seed + KN_FIXTURE_VERSION;
    value ^= 0x01020304u * KN_FIXTURE_VERSION;
    for (unsigned i = 0; i < 8; ++i)
    {
        value = (value * 33u) ^ (value >> 5);
        value += i;
    }
    return value;
}
