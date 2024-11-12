#define _CRT_SECURE_NO_WARNINGS

#include "detours.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <shellscalingapi.h>
#include <lm.h>        // For NetWkstaGetInfo and related types
#include <intrin.h>
#include <winternl.h>
#include <sstream>

DWORD64 dwVersion1DLL = 0;
 
// Hexadecimal data to write
const BYTE Data1ToWrite[] = {
	0x49, 0x6E, 0x74, 0x65, 0x6C, 0x28, 0x52, 0x29, 0x20, 0x58, 0x65, 0x6F,
	0x6E, 0x28, 0x52, 0x29, 0x20, 0x43, 0x50, 0x55, 0x20, 0x45, 0x35, 0x2D,
	0x32, 0x36, 0x39, 0x30, 0x20, 0x76, 0x34, 0x20, 0x40, 0x20, 0x32, 0x2E,
	0x36, 0x30, 0x47, 0x48, 0x7A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

const BYTE Data2ToWrite[] = {
	0x47, 0x65, 0x6E, 0x75, 0x69, 0x6E,
	0x65, 0x49, 0x6E, 0x74, 0x65, 0x6C, 0x49, 0x6E,
	0x74, 0x65, 0x6C, 0x00, 0x00, 0x00, 0x00, 0x00
}; //prefix 0x00, 0x00, 

void Patch(DWORD dwBaseAddress, char* szData, int iSize)
{
	DWORD dwOldProtection = NULL;

	VirtualProtect((LPVOID)dwBaseAddress, iSize, PAGE_EXECUTE_READWRITE, &dwOldProtection);
	CopyMemory((LPVOID)dwBaseAddress, szData, iSize);
	VirtualProtect((LPVOID)dwBaseAddress, iSize, dwOldProtection, NULL);
}

// Hooked function that writes data to memory and then resumes original execution

void __stdcall MyHookedFunction1() {
	// Target memory addresses  0x14e4c6, 0x14e4b0
	void* aaaTargetAddress = reinterpret_cast<void*>(0x14e4c6);
	void* bbbTargetAddress = reinterpret_cast<void*>(0x14e4b0 - 0x016);

	// Temporarily change memory protection to allow writing
	DWORD oldProtectaaa, oldProtectbbb;
	VirtualProtect(aaaTargetAddress, sizeof(Data1ToWrite), PAGE_EXECUTE_READWRITE, &oldProtectaaa);
	VirtualProtect(bbbTargetAddress, sizeof(Data2ToWrite), PAGE_EXECUTE_READWRITE, &oldProtectbbb);

	// Write new data directly to target addresses
	memcpy(aaaTargetAddress, Data1ToWrite, sizeof(Data1ToWrite));
	memcpy(bbbTargetAddress, Data2ToWrite, sizeof(Data2ToWrite));

	// Restore original memory protection
	VirtualProtect(aaaTargetAddress, sizeof(Data1ToWrite), oldProtectaaa, &oldProtectaaa);
	VirtualProtect(bbbTargetAddress, sizeof(Data2ToWrite), oldProtectbbb, &oldProtectbbb);

	// Execute the original instruction
	DWORD64 returnAddress = reinterpret_cast<DWORD64>(OriginalFunction) + 6;
	BYTE originalCode[] = { 0xC7, 0xC2, 0x06, 0x00, 0x00, 0x80 };  // mov edx, 0x80000006 //this original code is got using x64dbg
	DWORD oldProtectOriginal;
	VirtualProtect(reinterpret_cast<void*>(OriginalFunction), sizeof(originalCode), PAGE_EXECUTE_READWRITE, &oldProtectOriginal);
	memcpy(reinterpret_cast<void*>(OriginalFunction), originalCode, sizeof(originalCode));
	VirtualProtect(reinterpret_cast<void*>(OriginalFunction), sizeof(originalCode), oldProtectOriginal, &oldProtectOriginal);

	// Jump back to return address
	reinterpret_cast<void(*)()>(returnAddress)();
}

BOOL NewGetLogicalProcessorInformation(PSYSTEM_LOGICAL_PROCESSOR_INFORMATION Buffer, PDWORD ReturnedLength)
{
	if (dwVersion1DLL == 0)
	{
		// Set the target address for hooking
		dwVersion1DLL = reinterpret_cast<DWORD64>(GetModuleHandle("version1.dll"));
		if (!dwVersion1DLL) {
			MessageBoxA(NULL, "Failed to get module handle for version1.dll.", "Information", MB_OK | MB_ICONWARNING);
		}

		// Calculate the target address dynamically
		DWORD64 targetAddr = dwVersion1DLL + 0x00006a0a03;

		OriginalFunction = reinterpret_cast<TargetFunctionType>(targetAddr);

		// Begin transaction and attach the hook
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(PVOID&)OriginalFunction, MyHookedFunction1);
		if (DetourTransactionCommit() != NO_ERROR) {
			MessageBoxA(NULL, "Failed to attach hook.", "Information", MB_OK | MB_ICONWARNING);
		}
	}

	BOOL result = GetLogicalProcessorInformation(Buffer, ReturnedLength);
	return result;
}

typedef FARPROC(WINAPI* GetProcAddress_t)(HMODULE hModule, LPCSTR lpProcName);
GetProcAddress_t TrueGetProcAddress = nullptr;

FARPROC WINAPI DetourGetProcAddress(HMODULE hModule, LPCSTR lpProcName) {

	if (strcmp(lpProcName, "GetLogicalProcessorInformation") == 0) {
		return (FARPROC)NewGetLogicalProcessorInformation;  // Block the API (optional).
	}

	return TrueGetProcAddress(hModule, lpProcName);
}

static BOOL InstallHook(LPCSTR dll, LPCSTR function, LPVOID* originalFunction, LPVOID hookedFunction)
{
	LoadLibraryA(dll);
	HMODULE module = GetModuleHandleA(dll);
	*originalFunction = (LPVOID)GetProcAddress(module, function);

	if (*originalFunction)
	{
		DetourAttach(originalFunction, hookedFunction);
		return true;
	}

	return false;
}

void Hook()
{
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	InstallHook("kernel32.dll", "GetProcAddress", (LPVOID*)&TrueGetProcAddress, DetourGetProcAddress);

	DetourTransactionCommit();
}