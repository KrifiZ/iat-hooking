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

	return 0;
}
