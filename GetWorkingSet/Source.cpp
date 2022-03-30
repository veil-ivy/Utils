#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <Psapi.h>
#define PAGE_SIZE 0x1000
inline bool bget_privilege() {
	HANDLE htoken = NULL;
	LUID luid = { 0 };
	bool token = true;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &htoken)) {
		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
			TOKEN_PRIVILEGES tokenprivs = { 0 };
			tokenprivs.PrivilegeCount = 1;
			tokenprivs.Privileges[0].Luid = luid;
			tokenprivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			token = AdjustTokenPrivileges(htoken, FALSE, &tokenprivs, sizeof(TOKEN_PRIVILEGES), NULL, NULL);

		}
	}
	return token;
}
inline DWORD get_pid(const char* process_name) {
	if (process_name == NULL) {
		printf("failed to get process name\r\n");
		return 0;
	}
	DWORD pid = 0;
	PROCESSENTRY32 procinfo;
	procinfo.dwSize = sizeof(procinfo);
	HANDLE hsnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hsnapshot == INVALID_HANDLE_VALUE)
		return 0;
	
	if (!Process32First(hsnapshot ,&procinfo)) {
		CloseHandle(hsnapshot);
		return 0;
	}
	
	do {
		if (strcmp(process_name,procinfo.szExeFile )==0) {
			pid = procinfo.th32ParentProcessID;
			break;
		}
	} while (Process32Next(hsnapshot, &procinfo));
		CloseHandle(hsnapshot);
		return pid;
}
inline void print_working_set(PPSAPI_WORKING_SET_INFORMATION PWorkingSetInformation) {
	for (DWORD entries = 0; entries < PWorkingSetInformation->NumberOfEntries; entries++) {
		printf("memory page at VA  %p\r\n", PWorkingSetInformation->WorkingSetInfo[entries].VirtualPage);
		
	}
}
inline void working_set(HANDLE hprocess) {
	DWORD WorkingSetSize = 0;
	bool b= true;
	for (;;) {
		PSAPI_WORKING_SET_INFORMATION WorkingSetInfo;
		QueryWorkingSet(hprocess, &WorkingSetInfo, sizeof(PSAPI_WORKING_SET_BLOCK));
	
		PPSAPI_WORKING_SET_INFORMATION  PWorkingSetInformation;
		WorkingSetSize = sizeof(PSAPI_WORKING_SET_INFORMATION) + (sizeof(PSAPI_WORKING_SET_BLOCK) * WorkingSetInfo.NumberOfEntries);
		PWorkingSetInformation = (PPSAPI_WORKING_SET_INFORMATION)malloc(WorkingSetSize);
		ZeroMemory(PWorkingSetInformation, sizeof(PSAPI_WORKING_SET_INFORMATION));
		b = QueryWorkingSet(hprocess, (PVOID)PWorkingSetInformation, WorkingSetSize);
	
		if (!b) {
			printf("failed to query working set \r\n");
			return;
		}
		print_working_set(PWorkingSetInformation);
		if (GetLastError() == ERROR_BAD_LENGTH)
			return;
		free(PWorkingSetInformation);
	}
}
int main(int argc, char* argv[]) {
	if (!bget_privilege())
		ExitProcess(0);
	printf("GetWorkingSet  with <3 by @veil_ivy\r\n");
	printf("usage: process_name\r\n");
	printf("process name: name of the targeted process\r\n");
	DWORD dwpid=  get_pid(argv[1]);
	HANDLE hprocess = NULL;
	bool bstatus = false;
	DWORD workingset_size = 0;
	if (dwpid == 0) {
		printf("failed to get process\r\n");
		goto done;

	}
	hprocess = OpenProcess(GENERIC_ALL, FALSE, dwpid);
	if (hprocess == INVALID_HANDLE_VALUE) {
		printf("failed to open process\r\n");
		goto done;
	}
	working_set(hprocess);
	
done:
	ExitProcess(0);
	
}