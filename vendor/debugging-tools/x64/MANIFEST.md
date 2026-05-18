# Debugging Tools x64 Runtime Manifest

Source directory:

```text
C:\Program Files (x86)\Windows Kits\10\Debuggers\x64
```

Selected reason:

```text
Latest complete x64-compatible Debugging Tools runtime set found by tools\sync-debugging-tools-runtime.ps1.
The selection requires dbghelp.dll and symsrv.dll in the same directory and prefers x64 Debuggers paths.
If symsrv.yes is missing from the selected source, the script creates a one-byte consent marker.
msdia140.dll is selected separately from the newest installed Visual Studio DIA SDK x64 path.
```

Runtime files:

| File | Product version | Size | SHA-256 |
| --- | --- | ---: | --- |
| `dbgcore.dll` | `10.0.26100.2454` | 243280 | `046368578647E73E4BAE7CF5D4A9D3AF1DECB95E804B2F026B5253DE7F0E28B5` |
| `dbgeng.dll` | `10.0.26100.2454` | 9496104 | `812455CA25DDCAFF4BF9AD5E9372F3DECBC3878A450AFEE8F0FDB6C0CE67A7E7` |
| `dbghelp.dll` | `10.0.26100.2454` | 2254416 | `61FCFF65EA0F4D46B130C97CA1734350DB662485967B1656566A84C503E46A57` |
| `msdia140.dll` | `14.40.33807.0` | 2315184 | `9C06A43A03B413FC885BF05FAF7974B3BB8F8248507B3B51FDA6D9376EB7768B` |
| `srcsrv.dll` | `10.0.26100.2454` | 271936 | `5BD156B7634AFB54F568B0C82CC76B51F49BC2B9404472393A729BA4F37401EF` |
| `symsrv.dll` | `10.0.26100.2454` | 423504 | `A5DE07F62C855F109EACD5C783AD4C1067A930B5BD70EFDBA0247045D3A3A983` |
| `symsrv.yes` | `n/a` | 1 | `36A9E7F1C95B82FFB99743E0C5C4CE95D83C9A430AAC59F84EF3CBFAB6145068` |
