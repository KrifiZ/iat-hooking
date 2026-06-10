#include <Windows.h>
#include <cstdio>
#include <winnt.h>

int main() {
	HMODULE appHandle = GetModuleHandle(NULL);
	printf("Application handle: %p\n", appHandle);

	// Research on PE format structures
	// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
	PIMAGE_DOS_HEADER pdosHeader = (PIMAGE_DOS_HEADER)appHandle;
	if (pdosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("Invalid DOS signature\n");
		return 1;
	}

	printf("DOS header found\n");
	printf("e_lfanew offset: %d\n", pdosHeader->e_lfanew);

	// Parse NT headers
	PIMAGE_NT_HEADERS newTechnologyHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pdosHeader + pdosHeader->e_lfanew);

	// Check magic field for architecture
	if (newTechnologyHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		printf("Program for 32-bit\n");
	}
	else {
		printf("Program for 64-bit\n");
	}

	return 0;
}
