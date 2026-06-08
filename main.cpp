#include <Windows.h>
#include <cstdio>

int main() {
	HMODULE appHandle = GetModuleHandle(NULL);
	printf("Application handle: %p\n", appHandle);
	return 0;
}
