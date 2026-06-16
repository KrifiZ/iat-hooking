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

void printDllName(PIMAGE_IMPORT_DESCRIPTOR importDirectoryTable, PIMAGE_DOS_HEADER pdosHeader) {
	DWORD nameRVA = importDirectoryTable->Name;
	const char* dllName = (const char*)((BYTE*)pdosHeader + importDirectoryTable->Name);
	printf("-----dll name-----\n");
	printf("%s\n", dllName);
}

void printSystemVersion(PIMAGE_NT_HEADERS newTechnologyHeaders) {
	if (newTechnologyHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		printf("Program for 32-bit\n");
	}
	else {
		printf("Program for 64-bit\n");
	}
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
	/* Finding all structures from https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
		where there are no simple structures described in winnt.h, you have to guess by the byte sizes
		of structures. Variable names are not perfectly matched to how PE viewers look.
		Lots of own work and AI assistance.
	*/
	PIMAGE_DOS_HEADER pdosHeader = (PIMAGE_DOS_HEADER)appHandle;
	if (pdosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return 1;
	}

	PIMAGE_NT_HEADERS newTechnologyHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pdosHeader + pdosHeader->e_lfanew);

	printSystemVersion(newTechnologyHeaders);

	DWORD importRVA = newTechnologyHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	PIMAGE_IMPORT_DESCRIPTOR importDirectoryTable = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pdosHeader + importRVA);

	while (!IS_STRUCT_EMPTY(importDirectoryTable)) {
		PIMAGE_THUNK_DATA32 lookupTable = (PIMAGE_THUNK_DATA32)((BYTE*)pdosHeader + importDirectoryTable->OriginalFirstThunk);
		DWORD nameRVA = importDirectoryTable->Name;
		int sum = 0;
		const char* dllName = (const char*)((BYTE*)pdosHeader + importDirectoryTable->Name);
		if (strcmp(dllName, "USER32.dll") == 0) {
			while (!IS_STRUCT_EMPTY(lookupTable)) {
				PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)pdosHeader + lookupTable->u1.Function);
				if (strcmp(functionName->Name, "MessageBoxA") == 0) {
					lookupTable = (PIMAGE_THUNK_DATA32)((BYTE*)pdosHeader + importDirectoryTable->FirstThunk);
					lookupTable += sum;
					// This is used to unlock memory in IAT, not the memory in user32 which the function points to with an absolute address
					LPVOID lookupAddress = &(lookupTable->u1.Function);
					DWORD oldProtect;
					VirtualProtect(lookupAddress, sizeof & MessageBoxA, PAGE_EXECUTE_READWRITE, &oldProtect);

					(lookupTable->u1.Function) = (DWORD)fakeBox;

					VirtualProtect(lookupAddress, sizeof(DWORD), oldProtect, &oldProtect);

				}
				lookupTable++;
				sum++;
			}
		}
		importDirectoryTable = importDirectoryTable + 1;

	}
	MessageBoxA(NULL, "Hello there", "Window to be hooked", MB_OK);

	return 0;
}
