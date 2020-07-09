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
#include "detours.h"
#include <stdio.h>
#include <shlwapi.h>
#include <string>
#include <inttypes.h>

#pragma comment(lib, "Shlwapi.lib")

#define PAGE_EXECUTE_BACKDOOR 0x51
#define CALL_FIRST 1

typedef BOOL(*EXITPROC)(UINT);
EXITPROC exitProcAdd;

struct LibInitParams
{
	char targetFile[FILENAME_MAX];
	char runFlag[10];
	char dumpDir[FILENAME_MAX];
} initParams;

char logBuff[4096];
PVOID exceptHandle;

// Necessary so we don't interfere with detour libs...
bool ACTIVATE_HOOKS = FALSE;

#pragma region NativeMethods
void WriteLogFile(const char* logData)
{
	char logFileName[FILENAME_MAX];
	char* targetFileName = PathFindFileNameA(initParams.targetFile);
	PathRemoveExtensionA(targetFileName);

	sprintf_s(logFileName, sizeof(logFileName), "log_%s.txt", targetFileName);

	HANDLE hFile = CreateFileA(logFileName, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
		OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile != INVALID_HANDLE_VALUE) {
		DWORD bytesWritten;
		WriteFile(hFile, logData, (DWORD)strlen(logData), &bytesWritten, NULL);
		CloseHandle(hFile);
	}
}
#pragma endregion

#pragma region Hooks

static LPVOID(WINAPI * TrueVirtualAlloc)(
	LPVOID lpAddress, 
	SIZE_T dwSize, 
	DWORD flAllocationType, 
	DWORD flProtect
	) = VirtualAlloc;

static LPVOID(WINAPI * TrueVirtualAllocEx)(
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD flAllocationType,
	DWORD flProtect
	) = VirtualAllocEx;

static BOOL (WINAPI * TrueVirtualProtect)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flNewProtect,
	PDWORD lpflOldProtect
) = VirtualProtect;

static BOOL(WINAPI * TrueVirtualProtectEx)(
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flNewProtect,
	PDWORD lpflOldProtect
) = VirtualProtectEx;

LPVOID WINAPI HookVirtualAlloc(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD flAllocationType,
	DWORD flProtect
)
{
	bool resetPermissions = FALSE;
	if (flProtect == PAGE_EXECUTE_READWRITE && ACTIVATE_HOOKS) {
		flProtect = PAGE_READWRITE;
		resetPermissions = TRUE;
	}
	
	LPVOID result = TrueVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);

	if (resetPermissions) {
		sprintf_s(logBuff, sizeof(logBuff), "Modified PAGE_EXECUTE_READWRITE allocation with PAGE_READWRITE for allocation at address 0x%p...\n", result);
		WriteLogFile(logBuff);
	}
	return result;
}

LPVOID WINAPI HookVirtualAllocEx(
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD flAllocationType,
	DWORD flProtect
)
{
	bool resetPermissions = FALSE;
	if (flProtect == PAGE_EXECUTE_READWRITE && ACTIVATE_HOOKS) {
		flProtect = PAGE_READWRITE;
		resetPermissions = TRUE;
	}

	LPVOID result = TrueVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);

	if (resetPermissions) {
		sprintf_s(logBuff, sizeof(logBuff), "Modified PAGE_EXECUTE_READWRITE allocation with PAGE_READWRITE for allocation at address 0x%p...\n", result);
		WriteLogFile(logBuff);
	}

	return result;
}

BOOL WINAPI HookVirtualProtect(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flNewProtect,
	PDWORD lpflOldProtect
)
{
	bool resetPermissions = FALSE;
	if (flNewProtect == PAGE_EXECUTE_READWRITE && ACTIVATE_HOOKS) {
		flNewProtect = PAGE_READWRITE;
		resetPermissions = TRUE;
	}

	// Backdoor call from app to enable pass-through...
	if (flNewProtect == PAGE_EXECUTE_BACKDOOR) {
		flNewProtect = PAGE_EXECUTE_READWRITE;
	}

	BOOL result = TrueVirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);

	if (resetPermissions) {
		sprintf_s(logBuff, sizeof(logBuff), "Modified PAGE_EXECUTE_READWRITE allocation with PAGE_READWRITE for allocation at address 0x%p...\n", lpAddress);
		WriteLogFile(logBuff);
	}
	return result;
}

BOOL WINAPI HookVirtualProtectEx(
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flNewProtect,
	PDWORD lpflOldProtect
)
{
	bool resetPermissions = FALSE;
	if (flNewProtect == PAGE_EXECUTE_READWRITE && ACTIVATE_HOOKS) {
		flNewProtect = PAGE_READWRITE;
		resetPermissions = TRUE;
	}

	BOOL result = TrueVirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect);

	if (resetPermissions) {
		sprintf_s(logBuff, sizeof(logBuff), "Modified PAGE_EXECUTE_READWRITE allocation with PAGE_READWRITE for allocation at address 0x%p...\n", lpAddress);
		WriteLogFile(logBuff);
	}
	return result;
}

#pragma endregion

#pragma region VEH

LONG WINAPI VectoredHandler(struct _EXCEPTION_POINTERS *ExceptionInfo)
{
	UNREFERENCED_PARAMETER(ExceptionInfo);
	PCONTEXT context = ExceptionInfo->ContextRecord;
	DWORD errorCode = 0;

	#ifdef _WIN64
		DWORD64 instructionPointer = 0;
		instructionPointer = context->Rip++;
	#else
		DWORD instructionPointer = 0;
		instructionPointer = context->Eip++;
	#endif 

	errorCode = ExceptionInfo->ExceptionRecord->ExceptionCode;
	WriteLogFile("-----------------------------\n");
	sprintf_s(logBuff, sizeof(logBuff), "Exception Offset: 0x%p\nError Code: 0x%.8X\n", (void*)instructionPointer, errorCode);
	WriteLogFile(logBuff);

	if (errorCode == EXCEPTION_ACCESS_VIOLATION) {
		char fileName[FILENAME_MAX];
		char fullDumpPath[1024];
		MEMORY_BASIC_INFORMATION memInfo;
		SIZE_T regionSize = 0;
		DWORD dwWritten = 0;
		DWORD lpflOldProtect = 0;
		PVOID regionBase = 0;
		HANDLE hFile;

		char* targetFileName = PathFindFileNameA(initParams.targetFile);
		PathRemoveExtensionA(targetFileName);

		VirtualQuery(reinterpret_cast<PVOID>(instructionPointer), &memInfo, sizeof(memInfo));
		lpflOldProtect = memInfo.Protect;

		// To get the real size of the allocated memory block we walk through it, breaking when we step outside our previous allocation base
		regionBase = memInfo.AllocationBase;
		PVOID memWindow = memInfo.AllocationBase;
		while (true)
		{
			VirtualQuery(memWindow, &memInfo, sizeof(memInfo));
			if (regionBase != memInfo.AllocationBase) {
				break;
			}
			regionSize += memInfo.RegionSize;
			memWindow = (unsigned char *)memWindow + memInfo.RegionSize;
		}

		sprintf_s(fileName, sizeof(fileName), "dump_%s_0x%p_ep_0x%llX.bin", targetFileName, regionBase, (instructionPointer - (DWORD64)regionBase));
		sprintf_s(logBuff, sizeof(logBuff), "Writing %Iu bytes from 0x%p to %s...\n", regionSize, regionBase, fileName);
		WriteLogFile(logBuff);

		StrCpyA(fullDumpPath, initParams.dumpDir);
		lstrcatA(fullDumpPath, fileName);

		if (regionSize) {
			hFile = CreateFileA(fullDumpPath, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
			WriteFile(hFile, regionBase, (DWORD)regionSize, &dwWritten, NULL);
			CloseHandle(hFile);
			if (dwWritten == 0) {
				sprintf_s(logBuff, sizeof(logBuff), "There was a problem writing data to %s. Error 0x%.8X\n", fileName, GetLastError());
				WriteLogFile(logBuff);
				DeleteFileA(fullDumpPath);
			}
		}

		if (_stricmp(initParams.runFlag, "break") == 0) {
			HMODULE hMod = GetModuleHandleA("kernel32.dll");
			if (hMod == NULL) {
				sprintf_s(logBuff, sizeof(logBuff), "Could not aquire module handle. Error 0x%.8X\n", GetLastError());
				WriteLogFile(logBuff);
				return EXCEPTION_CONTINUE_SEARCH;
			}

			exitProcAdd = (EXITPROC)GetProcAddress(hMod, "ExitProcess");

			#ifdef _WIN64
				ExceptionInfo->ContextRecord->Rip = exitProcAdd(0);
			#else
				ExceptionInfo->ContextRecord->Eip = exitProcAdd(0);
			#endif 
		}
		else if (_stricmp(initParams.runFlag, "pass") == 0) {
			sprintf_s(logBuff, sizeof(logBuff), "Pass through on region 0x%p for instruction pointer 0x%p\n", regionBase, (void*)instructionPointer);
			WriteLogFile(logBuff);

			if (VirtualProtect(regionBase, regionSize, PAGE_EXECUTE_BACKDOOR, &lpflOldProtect)) {
				//VirtualQuery(reinterpret_cast<PVOID>(instructionPointer), &memInfo, sizeof(memInfo));
				//printf("Base Addr: 0x%p\n", memInfo.BaseAddress);
				//printf("AllocBase Addr: 0x%p\n", memInfo.AllocationBase);
				//printf("AllocPerms: 0x%X\n", memInfo.AllocationProtect);
				//printf("Mem Perms: 0x%X\n", memInfo.Protect);
				//printf("Mem State: 0x%X\n", memInfo.State);
				//printf("Region Size: 0x%X\n", memInfo.RegionSize);


				sprintf_s(logBuff, sizeof(logBuff), "Backdoor PAGE_EXECUTE_READWRITE success! Passing control back to 0x%p\n", (void*)instructionPointer);
				WriteLogFile(logBuff);

				#ifdef _WIN64
					ExceptionInfo->ContextRecord->Rip = instructionPointer;
				#else
					ExceptionInfo->ContextRecord->Eip = instructionPointer;
				#endif 
			}
			else {
				sprintf_s(logBuff, sizeof(logBuff), "Backdoor PAGE_EXECUTE_READWRITE failure! Error 0x%.8X\n", GetLastError());
				WriteLogFile(logBuff);
			}
		}
		WriteLogFile("-----------------------------\n");
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	WriteLogFile("-----------------------------\n");
	return EXCEPTION_CONTINUE_SEARCH;
}
#pragma endregion

extern "C" __declspec(dllexport) BOOL Initialize(LPVOID lpParam)
{
	LibInitParams myParams = *((LibInitParams*)lpParam);
	lstrcpyA(initParams.dumpDir, myParams.dumpDir);
	lstrcpyA(initParams.targetFile, myParams.targetFile);
	lstrcpyA(initParams.runFlag, myParams.runFlag);

	if (!CreateDirectoryA(initParams.dumpDir, NULL)) {
		if (GetLastError() != ERROR_ALREADY_EXISTS) {
			sprintf_s(logBuff, sizeof(logBuff), "Failed to create directory %s. Error 0x%.8X\n", initParams.dumpDir, GetLastError());
			WriteLogFile(logBuff);
			return FALSE;
		}
	}
	else {
		sprintf_s(logBuff, sizeof(logBuff), "Created directory %s\n", initParams.dumpDir);
		WriteLogFile(logBuff);
	}
	exceptHandle = AddVectoredExceptionHandler(CALL_FIRST, VectoredHandler);
	if (exceptHandle == NULL) {
		sprintf_s(logBuff, sizeof(logBuff), "Failed to create VEH! Error 0x%.8X\n", GetLastError());
		WriteLogFile(logBuff);
		return FALSE;
	}

	WriteLogFile("=============================\npicaboo hook library initialized!\n");
	return TRUE;
}

BOOL APIENTRY DllMain(HINSTANCE hInstance, DWORD  fdwReason, LPVOID lpReserved)
{
	long error;
	if (DetourIsHelperProcess()) {
		return TRUE;
	}

	switch (fdwReason)
	{
		case DLL_PROCESS_ATTACH:
		{
			//printf("Installing hooks...\n");
			DetourRestoreAfterWith();
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourAttach(&(PVOID&)TrueVirtualAlloc, HookVirtualAlloc);
			DetourAttach(&(PVOID&)TrueVirtualAllocEx, HookVirtualAllocEx);
			DetourAttach(&(PVOID&)TrueVirtualProtect, HookVirtualProtect);
			DetourAttach(&(PVOID&)TrueVirtualProtectEx, HookVirtualProtectEx);
			error = DetourTransactionCommit();
			ACTIVATE_HOOKS = TRUE;
			break;
		}

		case DLL_PROCESS_DETACH:
		{
			ACTIVATE_HOOKS = FALSE;
			//printf("Removing hooks...\n");
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourDetach(&(PVOID&)TrueVirtualAlloc, HookVirtualAlloc);
			DetourDetach(&(PVOID&)TrueVirtualAllocEx, HookVirtualAllocEx);
			DetourDetach(&(PVOID&)TrueVirtualProtect, HookVirtualProtect);
			DetourDetach(&(PVOID&)TrueVirtualProtectEx, HookVirtualProtectEx);
			error = DetourTransactionCommit();

			if (exceptHandle != NULL) {
				RemoveVectoredExceptionHandler(exceptHandle);
			}
			break;
		}
	}
	return TRUE;
}