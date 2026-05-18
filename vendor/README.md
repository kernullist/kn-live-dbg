# Vendor Runtime Folder

This folder contains pinned x64 Debugging Tools runtime files used by the build helper before falling back to the locally installed Windows Kits copy.

Current runtime set:

- `debugging-tools/x64/dbghelp.dll`
- `debugging-tools/x64/symsrv.dll`
- `debugging-tools/x64/dbgeng.dll`
- `debugging-tools/x64/dbgcore.dll`
- `debugging-tools/x64/msdia140.dll`
- `debugging-tools/x64/srcsrv.dll`
- `debugging-tools/x64/symsrv.yes`

The pinned `dbghelp.dll` and `symsrv.dll` pair is intentionally kept together. Mixing a newer System32 `dbghelp.dll` with an older or missing `symsrv.dll` can leave kernel PDB downloads at `SymNone`.
`symsrv.yes` is also pinned as the symbol-server consent marker. The sync script, build script, and EXE startup path create a one-byte marker when `symsrv.dll` exists but `symsrv.yes` is missing.
`msdia140.dll` is pinned from the Visual Studio DIA SDK x64 folder. The EXE registers it automatically with `DllRegisterServer` before symbol initialization in normal elevated runs. The symbol engine also supports no-reg DIA activation by loading the staged DLL directly and creating `IDiaDataSource` through `DllGetClassObject`.

Refresh this folder with:

```powershell
.\tools\sync-debugging-tools-runtime.ps1
```
