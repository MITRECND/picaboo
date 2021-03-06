/*
   Copyright(c) 2020 The MITRE Corporation. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
	   http://www.apache.org/licenses/LICENSE-2.0
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include <Windows.h>
#include <tlhelp32.h>
#include <Psapi.h>
#include <stdio.h>
#include <shlwapi.h>
#include <string.h>
#include <direct.h>

#pragma comment(lib, "Shlwapi.lib")

struct LibInitParams 
{
	char targetFile[FILENAME_MAX];
	char runFlag[10];
	char dumpDir[FILENAME_MAX];
} initParams;

const char* appName = "picaboo";

typedef VOID(*TARGETPROC)();
TARGETPROC targetProcAdd;

typedef BOOL(*INITIALIZE)(LibInitParams*);
INITIALIZE initProcAdd;

// Load our 'hook' libraries for our target DLL.
#ifdef _WIN64
	HINSTANCE hinstLib = LoadLibraryA("libs\\picaboo64.dll");
#else
	HINSTANCE hinstLib = LoadLibraryA("libs\\picaboo32.dll");
#endif

#define PAGE_EXECUTE_BACKDOOR 0x51

bool checkParentProc()
{
	char parentName[FILENAME_MAX];
	DWORD lpdwSize = FILENAME_MAX;
	DWORD pid = 0;
	DWORD crtPid = GetCurrentProcessId();
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	BOOL bContinue = Process32First(hSnapShot, &pe);

	while (bContinue) {
		if (crtPid == pe.th32ProcessID) {
			pid = pe.th32ParentProcessID;
		}
		pe.dwSize = sizeof(PROCESSENTRY32);
		bContinue = !pid && Process32Next(hSnapShot, &pe);
	}

	HANDLE hProcess = OpenProcess(
		SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
		FALSE, pe.th32ParentProcessID);

	if (QueryFullProcessImageNameA(hProcess, 0, parentName, &lpdwSize)) {
		char* parentExe = PathFindFileNameA(parentName);
		
		if (_strnicmp(parentExe, appName, strlen(appName)) == 0) {
			return true;
		}
	}
	else {
		printf("[*] Failed to get parent process. Error 0x%.8X\n", GetLastError());
	}
	return false;
}

void printHelp()
{
	printf("Usage: picaboo [RUN FLAG] [TARGET DLL/EXE/PIC] [TARGET PARAMETERS]\n");
	printf("[RUN FLAG] : [break|pass]\n");
	printf("\tbreak - Exit on first direct call into allocated memory address space.\n");
	printf("\tpass - Continue execution of target.\n");
	printf("[TARGET] : Path to the target file.\n");
	printf("[TARGET PARAMETERS] : Runtime parameters of the target. Context varies depending on the file type.\n");
	printf("\tdll  - Export entry of target DLL.\n");
	printf("\texe  - Runtime parameters to use for EXE.\n");
	printf("\tpic  - Offset to begin execution (must be specified in hex with '0x' prefix).\n");
	ExitProcess(0);
}

bool getMemDumpDir()
{
	if (!_getcwd(initParams.dumpDir, sizeof(initParams.dumpDir))) {
		printf("[*] Failed to get current directory. Error 0x%.8X\n", GetLastError());
		return false;
	}
	lstrcatA(initParams.dumpDir, "\\memdumps\\");
	return true;
}

const char* getPeType(const char* fileName)
{
	HANDLE hFile = CreateFileA(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	HANDLE hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);

	if (hFileMapping == NULL) {
		printf("[*] CreateFileMapping failed!\n");
		ExitProcess(0);
	}

	LPVOID lpFileBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);

	if (lpFileBase == NULL) {
		printf("[*] MapViewOfFile failed!\n");
		ExitProcess(0);
	}

	DWORD fileSize = GetFileSize(hFile, NULL);
	CloseHandle(hFile);
	CloseHandle(hFileMapping);

	if (sizeof(PIMAGE_DOS_HEADER) >= fileSize) {
		return "unknown";
	}

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpFileBase;
	if (sizeof(PIMAGE_DOS_HEADER) + pDosHeader->e_lfanew + sizeof(PIMAGE_NT_HEADERS) >= fileSize) {
		return "unknown";
	}

	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)pDosHeader + (DWORD_PTR)pDosHeader->e_lfanew);

	BOOL isWow64;
	IsWow64Process(GetCurrentProcess(), &isWow64);
	if (pNTHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
		if (!isWow64) {
			printf("[*] Target is incompatible with selected picaboo EXE. Use the 32bit version.\n");
			ExitProcess(0);
		}
	}
	if (pNTHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
		if (isWow64) {
			printf("[*] Target is incompatible with selected picaboo EXE. Use the 64bit version.\n");
			ExitProcess(0);
		}
	}

	if (pDosHeader->e_magic == 0x5a4d && pNTHeader->Signature == 0x4550) {
		if (pNTHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) {
			return "dll";
		}
		if (pNTHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) {
			return "exe";
		}
	}
	return "unknown";
}

void loadDLL(const char* exportName)
{
	initProcAdd = (INITIALIZE)GetProcAddress(hinstLib, "Initialize");
	if (initProcAdd == NULL) {
		printf("[*] Failed to initialize hook library.\n");
		ExitProcess(0);
	}
	if (!initProcAdd(&initParams)) {
		FreeLibrary(hinstLib);
		ExitProcess(0);
	}

	/*
	If the string specifies a module name without a path and the file name extension is omitted,
	the function appends the default library extension .dll to the module name.
	To prevent the function from appending .dll to the module name,
	include a trailing point character (.) in the module name string.
	https://msdn.microsoft.com/en-us/library/windows/desktop/ms684175.aspx
	*/
	char t_targetFile[FILENAME_MAX];
	lstrcpyA(t_targetFile, initParams.targetFile);
	strcat_s(t_targetFile, FILENAME_MAX, ".");

	printf("Loading %s with target %s...\n", initParams.targetFile, exportName);
	HINSTANCE targetLib = LoadLibraryA(t_targetFile);

	if (targetLib != NULL) {
		targetProcAdd = (TARGETPROC)GetProcAddress(targetLib, exportName);
		if (targetProcAdd != NULL) {
			printf("Successfully loaded target at 0x%p...\n", targetProcAdd);
			targetProcAdd();
		}
		else {
			printf("[*] Failed to load target function: %s. Error 0x%.8X\n", exportName, GetLastError());
		}
		FreeLibrary(targetLib);
	}
	else {
		printf("[*] Failed to load library: %s. Error 0x%.8X\n", initParams.targetFile, GetLastError());
	}
}

void loadEXE(char* peArguments)
{
	const char* libName;
	char runString[4096];
	STARTUPINFOA startupInfo = { sizeof(startupInfo) };
	PROCESS_INFORMATION processInfo;
	LPVOID lpAddress;
	HANDLE th;
	HMODULE hMod;

	StrCpyA(runString, initParams.targetFile);

	if (peArguments != NULL) {
		strcat_s(runString, sizeof(runString), " ");
		strcat_s(runString, sizeof(runString), peArguments);
	}

	printf("Executing run command: %s\n", runString);
	if (CreateProcessA(NULL, runString, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &startupInfo, &processInfo)) {

		BOOL isChildWow64;
		IsWow64Process(processInfo.hProcess, &isChildWow64);
		if (!isChildWow64) {
			libName = "libs\\picaboo64.dll";
		}
		else {
			libName = "libs\\picaboo32.dll";
		}

		// Load hook lib into the new process...
		hMod = GetModuleHandleA("kernel32.dll");
		if (hMod == NULL) {
			printf("[*] Failed to aquire module handle! Error 0x%.8X\n", GetLastError());
			TerminateProcess(processInfo.hProcess, 0);
			ExitProcess(0);
		}
		LPVOID loadLibraryFcn = GetProcAddress(hMod, "LoadLibraryA");
		SIZE_T libNameLen = strlen(libName) + 1;
		lpAddress = VirtualAllocEx(processInfo.hProcess, NULL, libNameLen, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (!lpAddress) {
			printf("[*] Failed to allocate memory inside new process. Error 0x%.8X\n", GetLastError());
			TerminateProcess(processInfo.hProcess, 0);
			ExitProcess(0);
		}
		if (!WriteProcessMemory(processInfo.hProcess, lpAddress, libName, libNameLen, NULL)) {
			printf("[*] Failed to write inject DLL name into new process. Error 0x%.8X\n", GetLastError());
			TerminateProcess(processInfo.hProcess, 0);
			ExitProcess(0);
		}

		/*
		64-bit versions of Windows use 32-bit handles for interoperability.
		When sharing a handle between 32-bit and 64-bit applications, only the lower 32 bits are significant,
		so it is safe to truncate the handle (when passing it from 64-bit to 32-bit)
		or sign-extend the handle (when passing it from 32-bit to 64-bit).
		https://docs.microsoft.com/en-us/windows/win32/winprog64/interprocess-communication
		*/

		// Load the hook library
		th = CreateRemoteThread(processInfo.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryFcn, lpAddress, 0, NULL);
		if (!th) {
			printf("[*] CreateRemoteThread failed for new process. Error 0x%.8X\n", GetLastError());
			TerminateProcess(processInfo.hProcess, 0);
			ExitProcess(0);
		}
		WaitForSingleObject(th, INFINITE);
		CloseHandle(th);
		printf("Injected %s into %s...\n", libName, initParams.targetFile);

		// Initialize the hook library with our parameters...
		hMod = GetModuleHandleA(libName);
		if (hMod == NULL) {
			printf("[*] Failed to aquire module handle! Error 0x%.8X\n", GetLastError());
			TerminateProcess(processInfo.hProcess, 0);
			ExitProcess(0);
		}
		LPVOID initializeFcn = GetProcAddress(hMod, "Initialize");
		SIZE_T initParamLen = sizeof(LibInitParams) + 1;
		lpAddress = VirtualAllocEx(processInfo.hProcess, NULL, initParamLen, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (!lpAddress) {
			printf("[*] Failed to allocate memory inside new process. Error 0x%.8X\n", GetLastError());
			TerminateProcess(processInfo.hProcess, 0);
			ExitProcess(0);
		}
		if (!WriteProcessMemory(processInfo.hProcess, lpAddress, &initParams, initParamLen, NULL)) {
			printf("[*] Failed to write initialization parameters into new process. Error 0x%.8X\n", GetLastError());
			TerminateProcess(processInfo.hProcess, 0);
			ExitProcess(0);
		}
		
		// Initialize library
		th = CreateRemoteThread(processInfo.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)initializeFcn, lpAddress, 0, NULL);
		if (!th) {
			printf("[*] CreateRemoteThread failed for new process. Error 0x%.8X\n", GetLastError());
			TerminateProcess(processInfo.hProcess, 0);
			ExitProcess(0);
		}
		WaitForSingleObject(th, INFINITE);
		CloseHandle(th);
		printf("Initialized %s!\n", libName);

		// Now resume that the hooked library has been initialized within the context of the process...
		ResumeThread(processInfo.hThread);
		WaitForSingleObject(processInfo.hProcess, INFINITE);
		CloseHandle(processInfo.hProcess);
		CloseHandle(processInfo.hThread);
	}
	else {
		printf("[*] Execution failed! Error 0x%.8X\n", GetLastError());
	}
}

void loadPIC(char* offset)
{
	HANDLE hFile;
	DWORD buffSize = 0;
	DWORD lpflOldProtect = 0;
	DWORD lpNumberOfBytesRead = 0;
	DWORD start = (DWORD)strtol(offset, NULL, 16);

	// Initialize hook libs
	initProcAdd = (INITIALIZE)GetProcAddress(hinstLib, "Initialize");
	if (initProcAdd == NULL) {
		printf("[*] Failed to initialize hook library.\n");
		ExitProcess(0);
	}
	if (!initProcAdd(&initParams)) {
		FreeLibrary(hinstLib);
		ExitProcess(0);
	}

	// Get handle to target
	hFile = CreateFileA(initParams.targetFile, GENERIC_READ, NULL, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[*] Failed to get handle to target! Error 0x%.8X\n", GetLastError());
		ExitProcess(0);
	}

	buffSize = GetFileSize(hFile, NULL);
	if (buffSize == INVALID_FILE_SIZE) {
		printf("[*] Invalid file size returned! Error 0x%.8X\n", GetLastError());
		CloseHandle(hFile);
		ExitProcess(0);
	}

	if (buffSize < start) {
		printf("[*] Offset is larger than selected file size!");
		CloseHandle(hFile);
		ExitProcess(0);
	}

	// Allocate memory address for file buffer
	LPVOID lpAddress = VirtualAlloc(NULL, buffSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!lpAddress) {
		printf("[*] Failed to allocate for PIC. Error 0x%.8X\n", GetLastError());
		CloseHandle(hFile);
		ExitProcess(0);
	}
	if (!VirtualProtect(lpAddress, buffSize, PAGE_EXECUTE_BACKDOOR, &lpflOldProtect)) {
		printf("[*] VirtualProtect of PIC target failed: %d\n", GetLastError());
	}
	
	if (!ReadFile(hFile, lpAddress, buffSize, &lpNumberOfBytesRead, NULL)) {
		printf("[*] Could not read from supplied PIC!");
		CloseHandle(hFile);
		ExitProcess(0);
	}

	char *ptrStart = (char*)lpAddress + start;
	printf("PIC loaded at 0x%p, executing...\n  HW offset: 0x%x\n  Virtual address: 0x%p", lpAddress, start, ptrStart);
	((void(*)(void))ptrStart)();

	CloseHandle(hFile);
}

int main(int argc, CHAR *argv[])
{
	DEP_SYSTEM_POLICY_TYPE policy = GetSystemDEPPolicy();
	if (policy != DEPPolicyAlwaysOn && policy != DEPPolicyOptOut) {
		printf("[*] You must enforce an 'ALWAYS ON' or 'OPT OUT' policy DEP policy to use this program. Please adjust your settings and reboot.\n");
		ExitProcess(0);
	}

	// Simple check against downstream execution inadvertently 
	// spawning another picaboo process and dumping the help contents.
	if (checkParentProc()) {
		ExitProcess(0);
	}

	if (argc != 4 && argc != 3) {
		printf("[*] Invalid number of arguments.\n");
		printHelp();
	}

	lstrcpyA(initParams.runFlag, argv[1]);
	if (_stricmp(initParams.runFlag, "break") != 0 && _stricmp(initParams.runFlag, "pass") != 0) {
		printf("[*] Please specify either break or pass for the [RUN FLAG].\n");
		printHelp();
	}

	lstrcpyA(initParams.targetFile, argv[2]);
	if (!PathFileExistsA(initParams.targetFile)) {
		printf("[*] Failed to find target file %s! Make sure it exists.\n", initParams.targetFile);
		ExitProcess(0);
	}

	if (!getMemDumpDir()) {
		ExitProcess(0);
	}

	const char* peType = getPeType(initParams.targetFile);
	if (_stricmp(peType, "dll") != 0 && _stricmp(peType, "exe") != 0) {
		printf("Proceeding as PIC and executing directly...\n");
	}

	if (hinstLib == NULL) {
		printf("[*] Failed to load hook DLL \'picaboo32.dll\' or \'picaboo64.dll\'.\n");
		printf("[*] Make sure it is in the same directory as the main program.\n");
		ExitProcess(0);
	}

	if (_stricmp(peType, "dll") == 0 && argc == 4) {
		loadDLL(argv[3]);
	}

	if (_stricmp(peType, "exe") == 0) {
		if (argc == 4) {
			loadEXE(argv[3]);
		}
		else {
			loadEXE(NULL);
		}
	}

	if (_stricmp(peType, "unknown") == 0 && argc == 4) {
		if (strlen(argv[3]) < 3 || (argv[3][0] != '0' && argv[3][1] != 'x')) {
			printf("[*] Offset must begin with '0x' to signify a hex offset has been used\n");
		}
		else {
			loadPIC(argv[3]);
		}
	}
	else if (_stricmp(peType, "unknown") == 0 && argc == 3) {
		printf("[*] You must provide an offset from which to begin execution in the target.");
	}
	FreeLibrary(hinstLib);
}
