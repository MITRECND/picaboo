# PICaboo

A Windows based dumper utility for malware analysts and reverse engineers whose aim is to dump crypted Position Independent Code (PIC).

## Overview

A typical barrier to the analysis of a malware family is getting past code designed to obfuscate later stages of the malware. Such programs are generally the by-product of 'crypters', and commonly decrypt and execute an embedded payload in memory. `picaboo` aims to help analysts by providing a means for analysts to inspect this code.

```
Usage: picaboo [RUN FLAG] [TARGET DLL/EXE/PIC] [TARGET PARAMETERS]
[RUN FLAG] : [break|pass]
        break - Exit on first direct call into allocated memory address space.
        pass - Continue execution of target.
[TARGET] : Path to the target file.
[TARGET PARAMETERS] : Runtime parameters of the target. Context varies depending on the file type.
        dll  - Export entry of target DLL.
        exe  - Runtime parameters to use for EXE.
        pic  - Offset to begin execution (must be specified in hex with '0x' prefix).
```

This program hooks and monitors calls to various Windows functions involved with the allocation of memory. It pays specific attention to new allocations that request `PAGE_EXECUTE_READWRITE` permissions. These permissions are usually requested by crypted executables that allocate memory for a buffer that is subsequently decrypted and executed. `picaboo` modifies these calls via an API hook, and changing the page permissions to `PAGE_READWRITE`. 

The following Windows functions are targeted:
* [VirtualAlloc](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc)
* [VirtualAllocEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)
* [VirtualProtect](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
* [VirtualProtectEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex)

When the crypted PE attempts to directly execute the decrypted buffer, an exception of type `EXCEPTION_ACCESS_VIOLATION` is thrown. Through the use of a [Vectorered Exception Handler](https://docs.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling) (VEH), this exception is intercepted, and the allocated memory is dumped to disk.

Depending on the runtime flag chosen, `picaboo` will do one of the following...
* `break` - Dump the memory block to disk and terminate the program by a direct call to `ExitProcess`.
* `pass` - Attempt to 'fix' the exception by assigning the originally requested permissions of `PAGE_EXECUTE_READWRITE` to the region of memory pointed to by the instruction pointer that forced the exception. The present `EIP/RIP` value is then set to the exception inducing instruction pointer. 
    * This is done via a call to `VirtualAlloc` using a 'backdoor' enum value the hook function monitors for.

Dumped memory regions are written to the `memdumps`, which is created in the same directory as the `picaboo` executable. The files are named according to the following convention.

dump_[FILENAME]\_[BASE ADDRESS]\_ep_[HW ENTRY POINT].bin

It should be noted here that the `AllocationBase` for the given memory region is what is used as the region starting point (not the `BaseAddress`). This ensures to the best degree possible a full accounting of data. The region size is computed by walking the entire region and accounting for all pages that map to the original `AllocationBase`. See the [MEMORY_BASIC_INFORMATION](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information) structure for more details. 

## Examples

### KerrDown Analysis

OSINT reporting on what Palo Alto has coined '[KerrDown](https://unit42.paloaltonetworks.com/tracking-oceanlotus-new-downloader-kerrdown/)' provides a good opportunity to pick on this malware family some more, and see how `picaboo` can assist an RE.

In KerrDown, Base64 encoded data is decoded and executed as PIC. Which reveals multiple modules leading to an attempt to download and execute more PIC.

If we take the cited SHA256 `040abac56542a2e0f384adf37c8f95b2b6e6ce3a0ff969e3c1d572e6b4053ff3` and unrar it, we can see the offending DLL `wwlib.dll` which is loaded and has its export function `FMain` executed by the executable `Noi dung chi tiet don khieu nai gui cong ty.exe`.

#### Getting KerrDown Next Stage

Let's say we are only interested in the next stage, we would execute with the run flag `break` as follows...

```
picaboo32.exe break .\samples\wwlib.dll FMain
Loading .\samples\wwlib.dll with target FMain...
Successfully loaded target at 0x6F571300...
```

Checking the log file generated for the file reveals a 8192 byte payload was dumped from memory.

```
=============================
picaboo hook library initialized!
Modified PAGE_EXECUTE_READWRITE allocation with PAGE_READWRITE for allocation at address 0x00160000...
-----------------------------
Exception Offset: 0x00160000
Error Code: 0xC0000005
Writing 8192 bytes from 0x00160000 to dump_wwlib_0x00160000_ep_0x0.bin...
```

#### Enumerating More KerrDown Plugins

But what if we want to continue execution? As cited by the original article, there are multiple stages here to analyze. This is where the `pass` command comes in handy.

Prior to execution in a victim VM, we can set up a service like [inetsim](https://www.inetsim.org/) to spoof DNS and HTTP responses on a separate VM, and configure the victim to solicit this host for those requests.

```
picaboo32.exe pass .\samples\wwlib.dll FMain
Loading .\samples\wwlib.dll with target FMain...
Successfully loaded target at 0x73931300...
```

A look at the log file...
```
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

As can be seen, multiple modules pop out that are directly executed. These have been dumped to disk in `memdumps`. Each module was encrypted or compressed at one point, however `picaboo` did the heavy lifting for us and dumped the unobfuscated modules to disk prior to execution. The RE can then piece together the sequence and begin a deeper dive.

### Bulk Processing
Bulk processing for multiple samples exhibiting a similar characteristic can be done easily with PowerShell.

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

### The Case of the Crypted PE

The following blog post from Malwarebytes on [Malware Crypters](https://blog.malwarebytes.com/threat-analysis/2015/12/malware-crypters-the-deceptive-first-layer/) provides a good opportunity to advertise `picaboo's` capabilities on a target executable.

One of the discussed samples (bearing MD5 1afb93d482fd46b44a64c9e987c02a27) is delivered by the Blackhole Exploit Kit and seems interesting, so let's run it through `picaboo`. 

```
picaboo32.exe pass .\samples\1afb93d482fd46b44a64c9e987c02a27.vt
Excuting run command: .\samples\1afb93d482fd46b44a64c9e987c02a27.vt
Injected picaboo32.dll into .\samples\1afb93d482fd46b44a64c9e987c02a27.vt...
Initialized picaboo32.dll!
```

Doing this allows the malware to continue running while we intercept allocated memory regions that are directly executed. Spinning up packet capture software like Wireshark should show periodic beacons to its configured callback.

Checking out the memdumps directory, we can see two payloads were allocated and executed. Further study of the final payload reveals an executable that is loaded and kicked off in memory! 

```
hexdump -Cv dump_1afb93d482fd46b44a64c9e987c02a27_0x00400000_ep_0x22C0.bin | less
00000000  4d 5a 90 00 03 00 00 00  04 00 00 00 ff ff 00 00  |MZ..............|
00000010  b8 00 00 00 00 00 00 00  40 00 00 00 00 00 00 00  |........@.......|
00000020  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000030  00 00 00 00 00 00 00 00  00 00 00 00 d0 00 00 00  |................|
00000040  0e 1f ba 0e 00 b4 09 cd  21 b8 01 4c cd 21 54 68  |........!..L.!Th|
00000050  69 73 20 70 72 6f 67 72  61 6d 20 63 61 6e 6e 6f  |is program canno|
00000060  74 20 62 65 20 72 75 6e  20 69 6e 20 44 4f 53 20  |t be run in DOS |
00000070  6d 6f 64 65 2e 0d 0d 0a  24 00 00 00 00 00 00 00  |mode....$.......|

```

Studying a bit closer, we can even see the callback address being assembled via stack strings...

```
seg000:00401A60 C7 05 A0 40+mov     ds:dword_4140A0, '4.87'
seg000:00401A60 41 00 37 38+
seg000:00401A60 2E 34
seg000:00401A6A 66 C7 05 A4+mov     ds:word_4140A4, '.6'
seg000:00401A6A 40 41 00 36+
seg000:00401A6A 2E
seg000:00401A73 A2 A6 40 41+mov     ds:byte_4140A6, al
seg000:00401A73 00
seg000:00401A78 C7 05 A7 40+mov     ds:dword_4140A7, '12.0'
seg000:00401A78 41 00 30 2E+
seg000:00401A78 32 31
seg000:00401A82 66 C7 05 AB+mov     ds:word_4140AB, '0'
```

### Fun With Shellcode

It's easy enough to experiment with PICaboo by writing your own loader for shellcode. 

```
#include <iostream>
#include <windows.h>
 
int main()
{
	DWORD lpflOldProtect;
	// I encrypted the shellcode used here: https://www.exploit-db.com/exploits/37758
	const char crypted[200] =
	"\x62\x98\x35\xda\x18\x61\xda\x18\x5d\xda\x18\x4d\xda\x08\x59"
	"\xda\x10\x71\xda\x58\xd1\x29\x5d\x62\x24\xa3\xda\xba\x52\x3c"
	// ... more shellcode here ...
	 
	// Allocate memory for our crypted code, notice here we only request read/write privs 
	LPVOID lpAddress = VirtualAlloc(NULL, sizeof(crypted), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	// Snag a pointer to our allocated region we will iterate on
	char *ptr = (char *)lpAddress;
	// Loop through the crypted buffer and decrypt the code
	for (int i = 0; i <= sizeof(crypted); i++) {
		*(ptr++) = crypted[i] ^ 0x51;
	}
 
	// Now elevate permissions to our decrypted buffer to execute
	if (!VirtualProtect((LPVOID)lpAddress, sizeof(crypted), PAGE_EXECUTE_READWRITE, &lpflOldProtect)) {
		printf("VirtualProtect failed: %d\n", GetLastError());
		return EXIT_FAILURE;
	}
 
	// Execute decryped shellcode...
	((void(*)(void))lpAddress)();
	return EXIT_SUCCESS;
}
```

Taking our initial proof of concept into account, we can simply begin by executing the compiled executable using the tool...

```
picaboo32.exe break poc.exe
Executing run command: poc.exe
Injected libs\picaboo32.dll into poc.exe...
Initialized libs\picaboo32.dll!
```

Looking at our logfile, we can see the memdump created.

```
picaboo hook library initialized!
Modified PAGE_EXECUTE_READWRITE allocation with PAGE_READWRITE for allocation at address 0x00110000...
-----------------------------
Exception Offset: 0x00110000
Error Code: 0xC0000005
Writing 4096 bytes from 0x00110000 to dump_poc_0x00110000_ep_0x0.bin...
```

This memory dump shows the deobfuscated shellcode. The idea is to get a dump of memory as it looks just prior to execution. For example, below is a snippet of the same crypted blob as above, decrypted, just prior to execution.
 
```
00000000  33 c9 64 8b 49 30 8b 49 0c 8b 49 1c 8b 59 08 8b  |3.d.I0.I..I..Y..|
00000010  41 20 8b 09 80 78 0c 33 75 f2 8b eb 03 6d 3c 8b  |A ...x.3u....m<.|
...
```

It disassembles cleanly beginning at the 0x0 offset, and we can see clearly the code begin walking the Process Environment Block (PEB) - typical shellcode stuff.

```
ndisasm -u dump.bin | less
00000000  33C9              xor ecx,ecx
00000002  648B4930          mov ecx,[fs:ecx+0x30]
00000006  8B490C            mov ecx,[ecx+0xc]
00000009  8B491C            mov ecx,[ecx+0x1c]
0000000C  8B5908            mov ebx,[ecx+0x8]
```

While we can continue to statically analyze this dump file, we also have the ability to just execute this directly using PICaboo. 

```
picaboo32.exe break .\memdumps\dump_poc_0x00110000_ep_0x0.bin 0x0
Proceeding as PIC and executing directly...
PIC loaded at 0x00100000, executing...
  HW offset: 0x0
  Virtual address: 0x00100000
```

Doing this simply executes the code directly, no further stages are dumped to disk. The only thing you get is a simple message window.


## Requirements

The `picaboo` DLLs are required, as they contain the necessary hooking functions. You will need to invoke either the 32 or 64 bit version of PICaboo depending on your target.

### DEP

You need to have DEP enabled on your host for this program to work effectively. You will receive an error from `picaboo` if DEP is not configured appropriately.

## Limitations

This project is still in its early stages, and was initially developed as a quick way to dump a large amount of crypted Position Independent Code (PIC) for further processing. 

The following assumptions are made concerning any prospective use case:

* The target is one of the following...
  * A DLL with an export function that does not take any arguments.
  * An EXE (arguments are permitted here).
  * Valid shellcode (your argument is the offset from which execution begins)
* Memory allocation or permission modification is made using one of the hooked Windows functions.
  * `PAGE_EXECUTE_READWRITE` permissions for the allocated region are requested.
* There are no dependencies on a parent process required by the target.

Depending on the functionality of the target, you may end up with a partially decrypted loader, or perhaps a small stub of shellcode that unwinds more code later. At a minimum you know the region dumped was marked for execution AND an attempt was made to do so.

Keep in mind also that depending on the functionality of the target, your results may be unpredictable (especially with the `pass` flag). It is always recommended to do these kinds of activities in a well isolated sandbox.

## Future Ideas

* Option to pass `EXCEPTION_CONTINUE_SEARCH` from VEH if we find ourselves stuck in an infinite loop. 
    * Malware that tries to erroneously execute code in a protected region for example will also produce an `EXCEPTION_ACCESS_VIOLATION`.
    
## Contributing

This project was developed using Visual Studio, so it is a good idea to install that and set it up before contributing. You will also need to download and compile detours as a library using `nmake` before and modifications are made to the injected payload. 

### Compiling Detours

Here are the steps that worked for me. 

* Get the latest version of [MS Detours](https://github.com/microsoft/Detours). Which is covered under the [MIT license](https://github.com/microsoft/Detours/blob/master/LICENSE.md).
* Navigate to build folder for Visual Studio `C:\Program Files (x86)\Microsoft Visual C++ Build Tools`. If you don't have it, you may have to [download](https://visualstudio.microsoft.com/downloads/) it. 
* Open `Visual C++ 2015 x86 Native Build Tools Command Prompt`
* Navigate to the Detours `src` directory and type `nmake`.
* Close and repeat the `nmake` process by opening `Visual C++ 2015 x64 Native Build Tools Command Prompt`.