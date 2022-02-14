#include <stdio.h>
#include <Windows.h>
#include <winioctl.h>

#define VADWALK_IOCTL_PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x501, METHOD_NEITHER,FILE_READ_DATA | FILE_WRITE_DATA)
typedef struct mem {
	ULONG pid;
}mem, * pmem;
int main(int argc,const char*argv[]) {
	DWORD pid = atoi(argv[1]);
	HANDLE hfile = CreateFile(L"\\\\.\\VadWalk", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hfile) {
		mem xmem = { 0 };
		xmem.pid = pid;
		DeviceIoControl(hfile, VADWALK_IOCTL_PID, &xmem, sizeof(mem), NULL, 0, 0,0);
	}
}