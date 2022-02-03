#pragma section(".CRT$XLY", long, read)
#include <stdio.h>
#include <Windows.h>
#pragma comment (lib, "User32.Lib")
#pragma comment (linker, "/SUBSYSTEM:windows /ENTRY:mainCRTStartup")

#define FLG_HEAP_ENABLE_TAIL_CHECK   0x10
#define FLG_HEAP_ENABLE_FREE_CHECK   0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40
#define NT_GLOBAL_FLAG_DEBUGGED (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)

PVOID GetPEB()
{
#ifdef _WIN64
	return (PVOID)__readgsqword(0x0C * sizeof(PVOID));
#else
	return (PVOID)__readfsdword(0x0C * sizeof(PVOID));
#endif
}

PVOID GetPEB64()
{
	PVOID pPeb = 0;
#ifndef _WIN64
	// 1. There are two copies of PEB - PEB64 and PEB32 in WOW64 process
	// 2. PEB64 follows after PEB32
	// 3. This is true for versions lower than Windows 8, else __readfsdword returns address of real PEB64

	BOOL isWow64 = FALSE;
	typedef BOOL(WINAPI* pfnIsWow64Process)(HANDLE hProcess, PBOOL isWow64);
	pfnIsWow64Process fnIsWow64Process = (pfnIsWow64Process)
		GetProcAddress(GetModuleHandleA("Kernel32.dll"), "IsWow64Process");
	if (fnIsWow64Process(GetCurrentProcess(), &isWow64)) {
		if (isWow64) {
			pPeb = (PVOID)__readfsdword(0x0C * sizeof(PVOID));
			pPeb = (PVOID)((PBYTE)pPeb + 0x1000);
		}
	}

#endif
	return pPeb;
}

void CheckNtGlobalFlag()
{
	PVOID pPeb = GetPEB();
	PVOID pPeb64 = GetPEB64();
	DWORD offsetNtGlobalFlag = 0;
#ifdef _WIN64
	offsetNtGlobalFlag = 0xBC;
#else
	offsetNtGlobalFlag = 0x68;
#endif
	DWORD NtGlobalFlag = *(PDWORD)((PBYTE)pPeb + offsetNtGlobalFlag);
	if (NtGlobalFlag & NT_GLOBAL_FLAG_DEBUGGED) {
		MessageBox(NULL, "Detect Debugging!", "NtGlobalFlag", MB_OK);
		exit(-1);
	}
	if (pPeb64) {
		DWORD NtGlobalFlagWow64 = *(PDWORD)((PBYTE)pPeb64 + 0xBC);
		if (NtGlobalFlagWow64 & NT_GLOBAL_FLAG_DEBUGGED) {
			MessageBox(NULL, "Detect Debugging!", "NtGlobalFlag", MB_OK);
			exit(-1);
		}
	}
}

int main()
{
	CheckNtGlobalFlag();
	MessageBox(NULL, "No Debugging!", "NtGlobalFlag", MB_OK);

	return 0;
}