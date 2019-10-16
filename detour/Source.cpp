/*
Copyright(c) 2019 The MITRE Corporation.All rights reserved.
MITRE Proprietary - Internal Use Only
TLP:Red and NDA Restrictions may apply.
For redistribution, specific permission is needed.
	   Contact: infosec@mitre.org

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED.IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
SUCH DAMAGE.
*/

#include <Windows.h>
#include "detours.h"
#include <stdio.h>
#include <shlwapi.h>
#include <string>

#pragma comment(lib, "Shlwapi.lib")

#define PAGE_EXECUTE_BACKDOOR 0x51

// Necessary so we don't interfere with detour libs...
bool ACTIVATE_HOOKS = false;

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
	bool resetPermissions = false;
	if (flProtect == PAGE_EXECUTE_READWRITE && ACTIVATE_HOOKS)
	{
		flProtect = PAGE_READWRITE;
		resetPermissions = true;
	}
	
	LPVOID result = TrueVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);

	if (resetPermissions)
	{
		printf("Modified PAGE_EXECUTE_READWRITE allocation with PAGE_READWRITE for allocation at address 0x%p...\n", result);
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
	bool resetPermissions = false;
	if (flProtect == PAGE_EXECUTE_READWRITE && ACTIVATE_HOOKS)
	{
		flProtect = PAGE_READWRITE;
		resetPermissions = true;
	}

	LPVOID result = TrueVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);

	if (resetPermissions)
	{
		printf("Modified PAGE_EXECUTE_READWRITE allocation with PAGE_READWRITE for allocation at address 0x%p...\n", result);
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
	bool resetPermissions = false;
	if (flNewProtect == PAGE_EXECUTE_READWRITE && ACTIVATE_HOOKS)
	{
		flNewProtect = PAGE_READWRITE;
		resetPermissions = true;
	}

	// Backdoor call from app to enable pass-through...
	if (flNewProtect == PAGE_EXECUTE_BACKDOOR)
	{
		flNewProtect = PAGE_EXECUTE_READWRITE;
	}

	BOOL result = TrueVirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);

	if (resetPermissions)
	{
		printf("Modified PAGE_EXECUTE_READWRITE allocation with PAGE_READWRITE for allocation at address 0x%p...\n", lpAddress);
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
	bool resetPermissions = false;
	if (flNewProtect == PAGE_EXECUTE_READWRITE && ACTIVATE_HOOKS)
	{
		flNewProtect = PAGE_READWRITE;
		resetPermissions = true;
	}

	BOOL result = TrueVirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect);

	if (resetPermissions)
	{
		printf("Modified PAGE_EXECUTE_READWRITE allocation with PAGE_READWRITE for allocation at address 0x%p...\n", lpAddress);
	}
	return result;
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
			printf("Installing hooks...\n");
			DetourRestoreAfterWith();
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourAttach(&(PVOID&)TrueVirtualAlloc, HookVirtualAlloc);
			DetourAttach(&(PVOID&)TrueVirtualAllocEx, HookVirtualAllocEx);
			DetourAttach(&(PVOID&)TrueVirtualProtect, HookVirtualProtect);
			DetourAttach(&(PVOID&)TrueVirtualProtectEx, HookVirtualProtectEx);
			error = DetourTransactionCommit();
			ACTIVATE_HOOKS = true;
			break;
		}

		case DLL_PROCESS_DETACH:
		{
			ACTIVATE_HOOKS = false;
			printf("Removing hooks...\n");
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourDetach(&(PVOID&)TrueVirtualAlloc, HookVirtualAlloc);
			DetourDetach(&(PVOID&)TrueVirtualAllocEx, HookVirtualAllocEx);
			DetourDetach(&(PVOID&)TrueVirtualProtect, HookVirtualProtect);
			DetourDetach(&(PVOID&)TrueVirtualProtectEx, HookVirtualProtectEx);
			error = DetourTransactionCommit();
			break;
		}
	}
	return true;
}