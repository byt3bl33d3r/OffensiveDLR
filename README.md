# OffensiveDLR

Toolbox containing research notes & PoC code for weaponizing .NET's DLR

## Contents

| Script | Description|
| --- | --- |
| `Invoke-JumpScare.ps1` | Executes shellcode using an embedded Boolang compiler, nothing touches disk (at least from what I've seen) and no calls to csc.exe are made :) |
| `Invoke-IronPython.ps1`  | Executes IronPython code using the embedded IPY engine. Same concept as `Invoke-JumpScare` only using IronPython. |
| `runBoo.cs` | C# version of `Invoke-JumpScare`. Executes shellcode using an embedded Boolang compiler.|
| `minidump.boo` | Native Boolang script to dump memory using `MiniDumpWriteDump` |
| `shellcode.boo`| Native Boolang script that executes shellcode. Currently contains 3 diffrent techniques (QueueUserAPC, CreateThread/WaitForSingleObject, WriteProcessMemory/CreateRemoteThread) |

## Why?
The .NET DLR is just straight up bonkers, it allows you to do crazy things like embed freaking compilers/engines within other .NET languages (e.g PowerShell & C#) while still remaining Opsec safe & staying in memory.
In IronPython's case, you can even have what I call 'engine inception': wanna embed a IPY engine within an IPY engine within another IPY engine? (yo dawg, I heard you liked IPY engines...).

From an offensive perspective this has an insane amount of flexibility and a number of advantages, to name a few:

1. Crazy amounts of reflection/embedding going on all the time, which means more evasion.

2. Using the DLR you always bypass AMSI (if you properly instrument your payloads), no need to obfuscate, patch stuff etc..

3. All your 'evil' can be coded in the language of your embedded engine/compiler. If you do this using PowerShell, ScriptBlock Logging sees nothing since all the magic happens in the DLR.

4. Usually, all of the DLR languages have a way of calling native methods either through the language itself or by dynamically compiling C# (e.g PowerShell's Add-Type).
   If you go with the former method, no calls to `csc.exe` are made and usually nothing is dropped to disk as the languages generate everything needed in memory through IL code.
   We can go as "...low and high as we want.." (@Op_nomad) & this allows us to do all the good stuff we all love (inject shellcode, unmanaged DLLs, load PEs etc..)

5. Allows for quick re-tooling and weaponization of payloads. No manual compilation is necessary.

# Other Offensive DLR projects

If you're interested in this, here's some other tools that also try to weponize the DLR:

- https://github.com/dsnezhkov/typhoon
- https://github.com/byt3bl33d3r/SILENTTRINITY

# Credits
 - @Op_nomad
 - @subtee
 - @pwndizzle
 - @malcomvetter
 - @harmj0y

##  References

Fair warning, if you start reading this stuff it's gonna send you down a hellish rabbit hole (with actual deamon rabbits)

- https://github.com/boo-lang/boo/wiki/Scripting-with-the-Boo.Lang.Compiler-API
- https://github.com/boo-lang/boo/wiki/Invoke-Native-Methods-with-DllImport
- https://github.com/pwndizzle/c-sharp-memory-injection
- http://www.voidspace.org.uk/ironpython/winforms/part10.shtm
- https://www.codeproject.com/Articles/53611/%2FArticles%2F53611%2FEmbedding-IronPython-in-a-C-Application
