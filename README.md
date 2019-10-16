# PICaboo

A Windows based dumper utility for malware analysts and reverse engineers whose aim is to dump crypted Position Independent Code (PIC).

## Overview

A typical barrier to the analysis of a malware family is getting past code designed to obfuscate later stages of the malware. Such programs are generally the by-product of 'crypters', which generally decrypt and execute an embedded payload in memory. PICaboo aims to help analysts by providing a means for analysts to inspect this code.

```
Usage: picaboo [RUN FLAG] [TARGET DLL] [DLL EXPORT FUNCTION]
[RUN FLAG] : [break|pass]
        break - Exit on first direct call into allocated memory address space.
        pass - Continue execution of target.
[TARGET] : Path to the target file.
[EXPORT FUNCTION] : What export function should be called?
```

This program hooks and monitors calls to various Windows fuctions involved with the allocation of memory. It pays specific attention to new allocations that request `PAGE_EXECUTE_READWRITE` permissions. These permissions are usually requested by crypted executables that allocate memory for a buffer that is subsequently decrypted and executed. picaboo modifies these calls via an API hook, and changing the page permissions to `PAGE_READWRITE`. 

The following Windows functions are targeted:
* [VirtualAlloc](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc)
* [VirtualAllocEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)
* [VirtualProtect](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
* [VirtualProtectEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex)

When the crypted PE attempts to directly execute the decrypted buffer, an exception of type `EXCEPTION_ACCESS_VIOLATION` is thrown. Through the use of a Vectorered Exception Handler (VEH), this exception is intercepted, and the allocated memory is dumped to disk.

Depending on the runtime flag chosen, picaboo will do one of the following...
* `break` - Dump the memory block to disk and terminate the program by a direct call to `ExitProcess`.
* `pass` - Attempt to 'fix' the exception by assigning the originally requested permissions of `PAGE_EXECUTE_READWRITE` to the region of memory pointed to by the instruction pointer that forced the exception. The present `EIP/RIP` value is then set to the exception inducing instruction pointer. 
    * This is done via a call to `VirtualAlloc` using a 'backdoor' enum value the hook function monitors for.

Dumped memory regions are written to the `memdumps`, which is created in the same directory as the `picaboo` executable. The files are named according to the following convention.

dump_[FILENAME]\_[BASE ADDRESS]\_ep_[HW ENTRY POINT].bin


## Examples

### KerrDown Analysis

OSINT reporting on what Palo Alto has coined '[KerrDown](https://unit42.paloaltonetworks.com/tracking-oceanlotus-new-downloader-kerrdown/)' provides a good opportunity to pick on this malware family some more, and see how `picaboo` can assist an RE.

In KerrDown, Base64 encoded data is executed as PIC. Which reveals multiple modules leading to an attempt to download and execute more PIC.

If we take the cited SHA256 `040abac56542a2e0f384adf37c8f95b2b6e6ce3a0ff969e3c1d572e6b4053ff3` and unrar it, we can see the offending DLL `wwlib.dll` which is loaded and has its export function `FMain` executed by the executable `Noi dung chi tiet don khieu nai gui cong ty.exe`.

#### Getting KerrDown Next Stage

Let's say we are only interested in the next stage, we would execute with the run flag `break` as follows...

```
picaboo32.exe break .\samples\wwlib.dll FMain
Installing hooks...
Loading .\samples\wwlib.dll with target FMain...
Successfully loaded target at 0x6F571300...
Modified PAGE_EXECUTE_READWRITE allocation with PAGE_READWRITE for allocation at address 0x00160000...
-----------------------------
Exception Offset: 0x00160000
Error Code: 0xC0000005
Writing 8192 bytes from 0x00160000 to dump_wwlib_0x00160000_ep_0x0.bin...
Removing hooks...
```

#### Enumerating More KerrDown Plugins

But what if we want to continue execution. As cited by the original article, there are multiple stages here to analyze. This is where the `pass` command comes in handy.

Prior to execution in a victim VM, we can set up a service like `inetsim` to spoof DNS and HTTP responses on a separate VM, and configure the victim to solicit this host for those requests.

```
picaboo32.exe pass .\samples\wwlib.dll FMain
Installing hooks...
Loading .\samples\wwlib.dll with target FMain...
Successfully loaded target at 0x73931300...
Modified PAGE_EXECUTE_READWRITE allocation with PAGE_READWRITE for allocation at address 0x00160000...
-----------------------------
Exception Offset: 0x00160000
Error Code: 0xC0000005
Writing 8192 bytes from 0x00160000 to dump_wwlib_0x00160000_ep_0x0.bin...
Pass through on region 0x00160000 for instruction pointer 0x00160000
Backdoor PAGE_EXECUTE_READWRITE success! Passing control back to 0x00160000
-----------------------------
Modified PAGE_EXECUTE_READWRITE allocation with PAGE_READWRITE for allocation at address 0x00170000...
-----------------------------
Exception Offset: 0x00170000
Error Code: 0xC0000005
Writing 8192 bytes from 0x00170000 to dump_wwlib_0x00170000_ep_0x0.bin...
Pass through on region 0x00170000 for instruction pointer 0x00170000
Backdoor PAGE_EXECUTE_READWRITE success! Passing control back to 0x00170000
-----------------------------
Modified PAGE_EXECUTE_READWRITE allocation with PAGE_READWRITE for allocation at address 0x00180000...
-----------------------------
Exception Offset: 0x00180000
Error Code: 0xC0000005
Writing 4096 bytes from 0x00180000 to dump_wwlib_0x00180000_ep_0x0.bin...
Pass through on region 0x00180000 for instruction pointer 0x00180000
Backdoor PAGE_EXECUTE_READWRITE success! Passing control back to 0x00180000
-----------------------------
Modified PAGE_EXECUTE_READWRITE allocation with PAGE_READWRITE for allocation at address 0x02260000...
-----------------------------
Exception Offset: 0x02260000
Error Code: 0xC0000005
Writing 10485760 bytes from 0x02260000 to dump_wwlib_0x02260000_ep_0x0.bin...
Pass through on region 0x02260000 for instruction pointer 0x02260000
Backdoor PAGE_EXECUTE_READWRITE success! Passing control back to 0x02260000
-----------------------------
-----------------------------
Exception Offset: 0x02260004
Error Code: 0xC0000096
-----------------------------
```

As can be seen, multiple modules pop out that are directly executed. Each module was encrypted or compressed at one point, however `picaboo` did the heavy lifting for us and dumped the unobfuscated modules to disk prior to execution. The RE can then piece together the sequence and begin a deeper dive.

### Bulk Processing
Bulk processing for multiple samples exhibiting a similar characteristic can be done easily by integrating with PowerShell.

```
param (
    [string]$runflag = "pass",
    [string]$target = ".",
    [string]$export = "test"
 )

$command = "C:\Users\test\picaboo32.exe"

$files = Get-ChildItem $target
foreach ($file in $files) 
{
    & "$command" "$runflag" "$file" "$export"
}
```

Point to your example directory and pass your target export function...
` C:\Users\test\iterate.ps1 pass samples/* FMain`

## Requirements

The detour DLLs are required, as they contain the necessary hooking functions. You will need to invoke either the 32 or 64 bit version of picaboo depending on your target.

## Limitations

This project is still in its early stages, and was initially developed as a quick way to dump a large amount of crypted Position Independent Code (PIC) for further processing. 

The following assumptions are made concerning any prospective use case:

* The target is a DLL with an export function that does not take any arguments.
* Memory allocation or permission modification is made using one of the hooked Windows functions.
  * `PAGE_EXECUTE_READWRITE` permissions for the allocated region are requested.

Depending on the functionality of the target, you may end up with a partially decrypted loader, or perhaps a small stub of shellcode that unwinds more code later. At a minimum you know the region dumped was marked for execution AND an attempt was made to do so.

Keep in mind also that depending on the functionality of the target, your results may be unpredictable (especially with the `pass` flag). It is always recommended to do these kind of activities in a well isolated sandbox.

## Future Ideas

* Compatability with executables.
* White listing memory regions specifically associated with certain modules (kernel32.dll, etc).
* Option to execute a file as PIC instead of requiring it be an EXE/DLL.
* Option to pass `EXCEPTION_CONTINUE_SEARCH` from VEH if we find ourselves stuck in an infinite loop. 
    * Malware that tries to erroneously execute code in a protected region for example will also produce an `EXCEPTION_ACCESS_VIOLATION`.
    
## Contributing

This project was developed using Visual Studio, so it is a good idea to install that and set it up before contributing. You will also need to download and compile detours as a library using `nmake` before and modifications are made to the injected payload. 

### Compiling Detours

Here are the steps that worked for me. 

* Get the latest version of [MS Detours](https://github.com/microsoft/Detours).
* Navigate to build folder for Visual Studio `C:\Program Files (x86)\Microsoft Visual C++ Build Tools`. If you don't have it, you may have to [download](https://visualstudio.microsoft.com/downloads/) it. 
* Open `Visual C++ 2015 x86 Native Build Tools Command Prompt`
* Navigate to the Detours `src` directory and type `nmake`.
* Close and repeat the `nmake` process by opening `Visual C++ 2015 x64 Native Build Tools Command Prompt`.