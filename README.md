# REPack

* Reverse Engieers toolkit for exploit/malware analysis

## IDA

| File | Description |
| :--- | :---------- |
| Analysis.py | |
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
| Notations-Load.py | |
| Notations-Save.py | |
| Notations-Show.py | |
| ResolveSymbolsFromDmp.py | |
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