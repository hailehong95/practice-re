#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <string.h>
#include <Windows.h>

void ShowUsage()
{
	printf("\nPE Mini Tools v2.0");
	printf("\nCopyright (C) 2017 Le Hong Hai\n");
	printf("\nUsage:\t PEMiniToolv2.exe [-Option] [Target]\n");
	printf("Option:\n");
	printf("   -help\t Help\n");
	printf("   -dos\t\t DOS Header Info\n");
	printf("   -sig\t\t Signature Info\n");
	printf("   -file\t File Header Info\n");
	printf("   -opt\t\t Optional Header Info\n");
	printf("   -sec\t\t Section Table Info\n");
	printf("   -import\t Import Functions\n");
	printf("   -export\t Export Functions\n");
}

int main(int argc, char const* argv[])
{
	HANDLE hFile, hMapObject;
	LPVOID lpBase; // Base Address
	PIMAGE_DOS_HEADER pDosHeader;	// 1. DOS Header
	PIMAGE_NT_HEADERS pNtHeader;	// 2. PE Header
	IMAGE_FILE_HEADER fileHeader;	// 2.2. FileHeader
	IMAGE_OPTIONAL_HEADER optionalHeader; // 2.3. Optional Header
	PIMAGE_SECTION_HEADER pSectionHeader; // 3. Section Table

	if (argc != 3) {
		ShowUsage();
		return 0;
	}

	hFile = CreateFileA(argv[2], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		// -1
		printf("CreateFile failed in read mode!\n");
		return 0;
	}

	hMapObject = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hMapObject == 0) {
		printf("CreateFileMapping failed!\n");
		CloseHandle(hFile);
		return 0;
	}

	lpBase = MapViewOfFile(hMapObject, FILE_MAP_READ, 0, 0, 0);
	if (lpBase == 0) {
		printf("MapViewOfFile failed!\n");
		CloseHandle(hMapObject);
		CloseHandle(hFile);
		return 1;
	}

	// Help
	if (!strcmp(argv[1], "-help")) {
		ShowUsage();
		return 0;
	}

	// PE DOS Header
	if (!strcmp(argv[1], "-dos")) {
		pDosHeader = (PIMAGE_DOS_HEADER)lpBase;

		if (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
			printf("---------------\n");
			printf("DOS Header Info\n");
			printf("---------------");
			printf("\ne_magic\t\t\t0x%x", pDosHeader->e_magic);
			printf("\ne_cblp\t\t\t0x%x", pDosHeader->e_cblp);
			printf("\ne_cp\t\t\t0x%x", pDosHeader->e_cp);
			printf("\ne_crlc\t\t\t0x%x", pDosHeader->e_crlc);
			printf("\ne_cparhdr\t\t0x%x", pDosHeader->e_cparhdr);
			printf("\ne_minalloc\t\t0x%x", pDosHeader->e_minalloc);
			printf("\ne_maxalloc\t\t0x%x", pDosHeader->e_maxalloc);
			printf("\n...\t\t\t...");
			printf("\ne_sp\t\t\t0x%x", pDosHeader->e_sp);
			printf("\ne_csum\t\t\t0x%x", pDosHeader->e_csum);
			printf("\ne_ip\t\t\t0x%x", pDosHeader->e_ip);
			printf("\ne_lfanew\t\t0x%x", pDosHeader->e_lfanew);
		}
	}

	// PE Signature
	if (!strcmp(argv[1], "-sig")) {
		pDosHeader = (PIMAGE_DOS_HEADER)lpBase;
		// pNTHeader = dosHeader + dosHeader->e_lfanew;
		pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)(pDosHeader)+(pDosHeader->e_lfanew));

		if (pNtHeader->Signature == IMAGE_NT_SIGNATURE) {
			printf("---------------\n");
			printf("NT Header Info\n");
			printf("---------------");
			printf("\nSignature\t\t0x%x (PE)", pNtHeader->Signature);
		}
	}

	// PE File Header
	if (!strcmp(argv[1], "-file")) {
		pDosHeader = (PIMAGE_DOS_HEADER)lpBase;
		pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)(pDosHeader)+(pDosHeader->e_lfanew));

		if (pNtHeader->Signature == IMAGE_NT_SIGNATURE) {
			fileHeader = pNtHeader->FileHeader;
			printf("---------------\n");
			printf("File Header Info\n");
			printf("---------------");
			printf("\nMachine\t\t\t\t0x%x", fileHeader.Machine);
			printf("\nNumberOfSections\t\t0x%x", fileHeader.NumberOfSections);
			printf("\nTimeDateStamp\t\t\t0x%x", fileHeader.TimeDateStamp);
			printf("\nPointerToSymbolTable\t\t0x%x", fileHeader.PointerToSymbolTable);
			printf("\nNumberOfSymbols\t\t\t0x%x", fileHeader.NumberOfSymbols);
			printf("\nSizeOfOptionalHeader\t\t0x%x", fileHeader.SizeOfOptionalHeader);
			printf("\nCharacteristics\t\t\t0x%x", fileHeader.Characteristics);
		}
	}

	// PE Optional Header
	if (!strcmp(argv[1], "-opt")) {
		pDosHeader = (PIMAGE_DOS_HEADER)lpBase;
		pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)(pDosHeader)+(pDosHeader->e_lfanew));
		optionalHeader = pNtHeader->OptionalHeader;

		printf("--------------------\n");
		printf("Optional Header Info\n");
		printf("--------------------");

		printf("\nMagic\t\t\t\t0x%x", optionalHeader.Magic);
		printf("\nSizeOfCode\t\t\t0x%x", optionalHeader.SizeOfCode);
		printf("\nSizeOfInitializedData\t\t0x%x", optionalHeader.SizeOfInitializedData);
		printf("\nSizeOfUninitializedData\t\t0x%x", optionalHeader.SizeOfUninitializedData);
		printf("\nAddressOfEntryPoint\t\t0x%x", optionalHeader.AddressOfEntryPoint);
		printf("\nBaseOfCode\t\t\t0x%x", optionalHeader.BaseOfCode);
		printf("\nBaseOfData\t\t\t0x%x", optionalHeader.BaseOfData);
		printf("\nImageBase\t\t\t0x%x", optionalHeader.ImageBase);
		printf("\nSectionAlignment\t\t0x%x", optionalHeader.SectionAlignment);
		printf("\nFileAlignment\t\t\t0x%x", optionalHeader.FileAlignment);
		printf("\nSizeOfImage\t\t\t0x%x", optionalHeader.SizeOfImage);
		printf("\nSizeOfHeaders\t\t\t0x%x", optionalHeader.SizeOfHeaders);
		printf("\nCheckSum\t\t\t0x%x", optionalHeader.CheckSum);
		printf("\nSubsystem\t\t\t0x%x", optionalHeader.Subsystem);
		printf("\nNumberOfRvaAndSizes\t\t0x%x", optionalHeader.NumberOfRvaAndSizes);
	}

	// PE Section Table
	if (!strcmp(argv[1], "-sec")) {
		pDosHeader = (PIMAGE_DOS_HEADER)lpBase;
		pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)(pDosHeader)+(pDosHeader->e_lfanew));

		printf("-------------------\n");
		printf("Section Header Info\n");
		printf("-------------------\n");

		pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
		int iCount = 0;
		int TotalSection = pNtHeader->FileHeader.NumberOfSections;

		printf("Name\t  VirtualSize\t VirtualAddress(RVA)\t   RawSize\t RawAddress\t Characteristics");
		for (pSectionHeader, iCount; iCount < TotalSection; pSectionHeader++, iCount++) {
			printf("\n%s", pSectionHeader->Name);
			printf("\t   0x%x", pSectionHeader->Misc.VirtualSize);
			printf("\t\t0x%x", pSectionHeader->VirtualAddress);
			printf("\t\t    0x%x", pSectionHeader->SizeOfRawData);
			printf("\t   0x%x", pSectionHeader->PointerToRawData);
			printf("\t    0x%x", pSectionHeader->Characteristics);
		}
	}

	// Import Functions
	if (!strcmp(argv[1], "-import")) {
		pDosHeader = (PIMAGE_DOS_HEADER)lpBase;
		pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)(pDosHeader)+(pDosHeader->e_lfanew));
		optionalHeader = pNtHeader->OptionalHeader;
		DWORD dwSectionCount = pNtHeader->FileHeader.NumberOfSections;
		DWORD dwSection, dwImportDirectoryVA, dwRawOffset;
		PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor;

		/*
		#define IMAGE_DIRECTORY_ENTRY_EXPORT	0
		#define IMAGE_DIRECTORY_ENTRY_IMPORT	1
		*/

		if (optionalHeader.Magic == 0x10b) {
			// PE 32 bit
			// Get Virtual Address of Import Directory
			dwImportDirectoryVA = pNtHeader->OptionalHeader.DataDirectory[1].VirtualAddress;
			pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pNtHeader + sizeof(IMAGE_NT_HEADERS32));

			for (dwSection = 0; dwSection < dwSectionCount && pSectionHeader->VirtualAddress <= dwImportDirectoryVA; pSectionHeader++, dwSection++);
			pSectionHeader--;
			dwRawOffset = (DWORD)lpBase + pSectionHeader->PointerToRawData;
			pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(dwRawOffset + (dwImportDirectoryVA - pSectionHeader->VirtualAddress));

			printf("---------------------\n");
			printf("Import Directory Info\n");
			printf("---------------------");
			for (; pImportDescriptor->Name != 0; pImportDescriptor++) {
				DWORD DLLName = dwRawOffset + (pImportDescriptor->Name - pSectionHeader->VirtualAddress);
				printf("\nModule Name: %s\n", DLLName);

				PIMAGE_THUNK_DATA32 pThunkData32 = (PIMAGE_THUNK_DATA32)(dwRawOffset + (pImportDescriptor->FirstThunk - pSectionHeader->VirtualAddress));
				for (; pThunkData32->u1.AddressOfData != 0; pThunkData32++) {
					DWORD FunctionName = (dwRawOffset + (pThunkData32->u1.AddressOfData - pSectionHeader->VirtualAddress + 2));
					printf("\t%s\n", FunctionName);
				}

			}
		}

	}

	// Export Functions
	if (!strcmp(argv[1], "-export")) {
		pDosHeader = (PIMAGE_DOS_HEADER)lpBase;
		pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)(pDosHeader)+(pDosHeader->e_lfanew));
		optionalHeader = pNtHeader->OptionalHeader;

		DWORD dwSectionCount = pNtHeader->FileHeader.NumberOfSections;
		DWORD dwExportDirectoryVA, dwSection = 0, dwRawOffset;
		PIMAGE_EXPORT_DIRECTORY pExportDirectory;
		PIMAGE_SECTION_HEADER pSecHeaderForExport;

		if (optionalHeader.Magic == 0x10b) {
			// PE 32 bit
			pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pNtHeader + sizeof(IMAGE_NT_HEADERS32));
			dwSectionCount = pNtHeader->FileHeader.NumberOfSections;
			dwExportDirectoryVA = pNtHeader->OptionalHeader.DataDirectory[0].VirtualAddress;

			for (; dwSection < dwSectionCount && pSectionHeader->VirtualAddress <= dwExportDirectoryVA; dwSection++, pSectionHeader++);
			pSectionHeader--;
			pSecHeaderForExport = pSectionHeader;
			dwRawOffset = (DWORD)lpBase + pSecHeaderForExport->PointerToRawData;
			pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(dwRawOffset + (dwExportDirectoryVA - pSecHeaderForExport->VirtualAddress));

			printf("---------------------\n");
			printf("Export Directory Info\n");
			printf("---------------------\n");

			if (pExportDirectory->AddressOfFunctions != NULL) {
				PULONG Name = (PULONG)((PUCHAR)dwRawOffset + (pExportDirectory->AddressOfNames - pSecHeaderForExport->VirtualAddress));
				printf("Export Functions: \n");
				for (int i = 0; i < pExportDirectory->NumberOfNames; i++) {
					DWORD FunctionName = dwRawOffset + ((char*)Name[i] - pSecHeaderForExport->VirtualAddress);
					printf("\t%s\n", FunctionName);
				}
			}
		}
	}

	UnmapViewOfFile(lpBase);
	CloseHandle(hMapObject);
	CloseHandle(hFile);
	return 0;
}