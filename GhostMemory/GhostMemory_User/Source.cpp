#include <Windows.h>
#include <winioctl.h>
#include <stdio.h>
#define KGHOST_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN,0x601,METHOD_NEITHER,FILE_READ_DATA | FILE_WRITE_DATA)
typedef struct kghost_mem {

	ULONG pid;
	char* alloc_buffer;
	SIZE_T alloc_size;
}kghost_mem, * pkghost_mem;

typedef struct kghost {
	PVOID VA;
}kghost, * pkghost;
int main() {
	UCHAR buffer[] = { 0x90,0x90,0x90};
	ULONG dwpid = GetCurrentProcessId();
	kghost_mem kgm = { 0 };
	LPVOID ret_buffer = (LPVOID)malloc(sizeof(kghost));
	ZeroMemory(ret_buffer, sizeof(kghost));
	DWORD ret = 0;
	pkghost pkg=NULL;
	kgm.alloc_buffer = (char*)malloc(sizeof(buffer));
	kgm.alloc_size = sizeof(buffer)+1;
	CopyMemory(kgm.alloc_buffer, buffer, sizeof(buffer));
	kgm.pid = GetCurrentProcessId();
	HANDLE hfile = CreateFile(L"\\\\.\\ghost_injector", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	DeviceIoControl(hfile, KGHOST_MEMORY, &kgm, sizeof(kghost_mem), ret_buffer, sizeof(kghost), &ret, NULL);
	pkg = (pkghost)ret_buffer;
	printf("ghost memory allocated at => %p", pkg->VA);
	system("pause");
	ExitProcess(0);
}