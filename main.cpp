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

void printSystemVersion(PIMAGE_NT_HEADERS newTechnologyHeaders) {
	if (newTechnologyHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		printf("Program for 32-bit\n");
	}
	else {
		printf("Program for 64-bit\n");
	}
}

void printDllName(PIMAGE_IMPORT_DESCRIPTOR importDirectoryTable, PIMAGE_DOS_HEADER pdosHeader) {
	const char* dllName = (const char*)((BYTE*)pdosHeader + importDirectoryTable->Name);
	printf("-----dll name-----\n");
	printf("%s\n", dllName);
}

void printDllFunctionsName(PIMAGE_THUNK_DATA32 lookupTable, PIMAGE_DOS_HEADER pdosHeader) {
	printf("-----functions-----\n");
	while (!IS_STRUCT_EMPTY(lookupTable)) {
		PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)pdosHeader + lookupTable->u1.Function);
		printf("%s \n", functionName->Name);
		lookupTable += 1;
	}
}

typedef int (WINAPI* MessageBoxA_fn)(HWND, LPCSTR, LPCSTR, UINT);

int WINAPI fakeBox(HWND, LPCSTR, LPCSTR, UINT) {
	printf("Hook works!\n");
	return 0;
}

int main() {
	HMODULE appHandle = GetModuleHandle(NULL);
	printf("Application handle: %p\n", appHandle);

	PIMAGE_DOS_HEADER pdosHeader = (PIMAGE_DOS_HEADER)appHandle;
	if (pdosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("Invalid DOS signature\n");
		return 1;
	}

	printf("DOS header found\n");

	// Parse NT headers using byte representation from MSDN
	PIMAGE_NT_HEADERS newTechnologyHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pdosHeader + pdosHeader->e_lfanew);

	printSystemVersion(newTechnologyHeaders);

	// Get Import Directory Table address from DataDirectory
	DWORD importRVA = newTechnologyHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	PIMAGE_IMPORT_DESCRIPTOR importDirectoryTable = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pdosHeader + importRVA);

	// Search for USER32.dll and attempt to hook MessageBoxA
	while (!IS_STRUCT_EMPTY(importDirectoryTable)) {
		const char* dllName = (const char*)((BYTE*)pdosHeader + importDirectoryTable->Name);
		if (strcmp(dllName, "USER32.dll") == 0) {
			printDllName(importDirectoryTable, pdosHeader);

			// Iterate through thunk table for function names
			PIMAGE_THUNK_DATA32 lookupTable = (PIMAGE_THUNK_DATA32)((BYTE*)pdosHeader + importDirectoryTable->OriginalFirstThunk);
			int sum = 0;
			while (!IS_STRUCT_EMPTY(lookupTable)) {
				PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)pdosHeader + lookupTable->u1.Function);
				printf("%s \n", functionName->Name);

				if (strcmp(functionName->Name, "MessageBoxA") == 0) {
					printf("Found MessageBoxA at index %d\n", sum);
				}

				lookupTable += 1;
				sum++;
			}
		}

		importDirectoryTable = importDirectoryTable + 1;
	}

	return 0;
}
