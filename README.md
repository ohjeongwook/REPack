# REPack

Reverse engineering toolkit for exploit/malware analysis

## IDA

| File | Description |
| :--- | :---------- |
| Analysis.py | Main IDA functionality wrapper file |
| AutoAnalysis-ImmedatesToRefs.py | |
| Breakpoints-All-DisplacementCalls.py | |
| Breakpoints-All-IndirectCalls.py | |
| Breakpoints-All-MemoryAccess.py | |
| Breakpoints-CurrentInstruction.py | |
| Breakpoints-Functions.py | |
| Breakpoints-FunctionTree-IndirectCalls.py | |
| Breakpoints-FunctionTree-MemoryAccess.py | |
| Breakpoints-InterestingPoints.py | |
| Breakpoints-Log-Load.py | |
| Breakpoints.py | |
| DumpCurrentInstruction.py | |
| FindInstructions-CallToDS.py | |
| FunctionTree-GUI.py | |
| FunctionTree.py | |
| Hunting-EncodingInstructions.py | |
| Hunting-Loops.py | |
| Hunting.py | |
| List-Export.py | |
| List.py | |
| Notations-Load.py | Load notations (function name, address name, comment) from a SQLite file |
| Notations-Save.py | Save notations (function name, address name, comment) as a SQLite file |
| Notations-Show.py | Show notations (function name, address name, comment) from a SQLite file |
| ResolveSymbolsFromDmp.py | Resolve unresolved symbols by leveraing process dump file |
| RunIDAScript.py | |
| Server.py | |
| UI.py | |

## PE

| File | Description |
| :--- | :---------- |
| PETool.py | Tool to fix section from the carved PE image |

### Examples

1. Fix section from PE image filemsidntfs

The msidntfs.bin is a carved PE image from an infected process. Use PETool.py to fix sections and align them so that the file can be opened from PE reverse engineering tools like IDA.

```
%REPACK%\Src\PE\PETool.py -c fix msidntfs.bin msidntfs.fixed.bin
```

## WinDBG

| File | Description |
| :--- | :---------- |
| Breakpoints.py | |
| Command.py | |
| Install.md | |
| Log.py | |
| PyKD.py | |
| Util\WindbgKernelPipe.cmd | |