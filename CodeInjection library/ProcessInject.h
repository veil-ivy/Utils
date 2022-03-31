#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <winternl.h>
#pragma comment(lib,"ntdll.lib")
namespace Inject {
	BOOL SeDbugPrivs();
	DWORD GetPidByName(WCHAR *proc_name);
	HANDLE GetHandle(DWORD pid);
	class DllInject {
	public:
		BOOL RemoteThreadDllInject(DWORD pid,char *dllPath);
	};
	class CodeInject {
	public:
		BOOL RemoteThreadShellcodeInject(DWORD pid,unsigned char *shellcode,DWORD size);
		BOOL LocalAPCQueInjection(unsigned char * shellcode,DWORD size);
		BOOL ApcQueInjection(DWORD pid, unsigned char *shellcode, DWORD size);
		BOOL WordWarping(LPVOID payload, DWORD payload_size);
	
	};
	class Memory_Surviliance {
	public:
		BOOL IsCodePtr(HANDLE hp, LPVOID ptr);
		BOOL IsHeapPtr(LPVOID ptr);
		BOOL IsRWX(LPVOID ptr,BOOL Heap);
		IMAGE_SECTION_HEADER DataSection(LPVOID module, DWORD pointers);
		LPVOID RemoteDataSection(HANDLE process, DWORD pointers);
		LPVOID GetProcessBase(HANDLE ProcHandle);
		LPVOID GetRemoteModule(DWORD pid, const wchar_t *RemoteModule);
		
	};
	
}
namespace Tricks {
	class PEBTricks {

	};
}