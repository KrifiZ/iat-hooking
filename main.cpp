#include <Windows.h>
#include <cstdio>
#include <winnt.h>

bool isEmpty(BYTE* importVal, size_t size) {
	size_t sum = 0;
	for (size_t i = 0; i < size; i++) {
		if (importVal[i] == NULL)
			sum++;
	}
	if (sum == size) {
		return 1;
	}
	return 0;
}
#define IS_STRUCT_EMPTY(ptr) isEmpty((BYTE*)ptr, sizeof *ptr )

int main() {
	HMODULE appHandle = GetModuleHandle(NULL);
	printf("Application handle: %p\n", appHandle);

	PIMAGE_DOS_HEADER pdosHeader = (PIMAGE_DOS_HEADER)appHandle;
	if (pdosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("Invalid DOS signature\n");
		return 1;
	}

	printf("DOS header found\n");

	// Parse NT headers
	PIMAGE_NT_HEADERS newTechnologyHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pdosHeader + pdosHeader->e_lfanew);

	// Check magic field for architecture
	if (newTechnologyHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		printf("Program for 32-bit\n");
	}
	else {
		printf("Program for 64-bit\n");
	}

	// Get Import Directory Table address from DataDirectory
	DWORD importRVA = newTechnologyHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	PIMAGE_IMPORT_DESCRIPTOR importDirectoryTable = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pdosHeader + importRVA);

	printf("Import Directory Table found\n");

	// Iterate through imported DLLs
	while (!IS_STRUCT_EMPTY(importDirectoryTable)) {
		const char* dllName = (const char*)((BYTE*)pdosHeader + importDirectoryTable->Name);
		printf("DLL: %s\n", dllName);
		importDirectoryTable = importDirectoryTable + 1;
	}

	return 0;
}
