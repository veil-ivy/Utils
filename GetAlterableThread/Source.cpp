#include <ntifs.h>
PETHREAD AlterableThread=NULL;
bool bfound = false;
namespace offsets {
	/*
	0: kd > dt nt!_EPROCESS ffffd40a328e42c0 ThreadListHead
		+ 0x5e0 ThreadListHead : _LIST_ENTRY[0xffffd40a`30faa568 - 0xffffd40a`2f1ea568]
	*/
	const unsigned int eprocess_list_head_offset = 0x5e0;
	/*
	0: kd > dt nt!_ETHREAD
		+ 0x000 Tcb              : _KTHREAD
	*/
	/*
	0: kd > dt nt!_ethread threadlistentry
		+ 0x4e8 threadlistentry : _list_entry
	*/
	const unsigned int ethread_list_entry_offset = 0x4e8;
	/*
	0: kd > dt nt!_KTHREAD
		+ 0x000 Header           : _DISPATCHER_HEADER
		+ 0x018 SListFaultAddress : Ptr64 Void
		+ 0x020 QuantumTarget : Uint8B
		+ 0x028 InitialStack : Ptr64 Void
		+ 0x030 StackLimit : Ptr64 Void
		+ 0x038 StackBase : Ptr64 Void
		+ 0x040 ThreadLock : Uint8B
		+ 0x048 CycleTime : Uint8B
		+ 0x050 CurrentRunTime : Uint4B
		+ 0x054 ExpectedRunTime : Uint4B
		+ 0x058 KernelStack : Ptr64 Void
		+ 0x060 StateSaveArea : Ptr64 _XSAVE_FORMAT
		+ 0x068 SchedulingGroup : Ptr64 _KSCHEDULING_GROUP
		+ 0x070 WaitRegister : _KWAIT_STATUS_REGISTER
		+ 0x071 Running : UChar
		+ 0x072 Alerted : [2] UChar
		+ 0x074 AutoBoostActive : Pos 0, 1 Bit
		+ 0x074 ReadyTransition : Pos 1, 1 Bit
		+ 0x074 WaitNext : Pos 2, 1 Bit
		+ 0x074 SystemAffinityActive : Pos 3, 1 Bit
		+ 0x074 Alertable : Pos 4, 1 Bit

		*/
	const unsigned int kthread_alertable = 0x074;


	//0: kd > dt nt!_EPROCESS ActiveProcessLinks
	//	+ 0x448 ActiveProcessLinks : _LIST_ENTRY
	const unsigned int eprocess_active_process_links = 0x448;




	//0: kd > dt nt!_EPROCESS ImageFileName
	//	+ 0x5a8 ImageFileName : [15] UChar

	const unsigned int eprocess_image_file_name_offset = 0x5a8;

}

auto drv_unload(PDRIVER_OBJECT DriverObject)->void {
	UNREFERENCED_PARAMETER(DriverObject);
}

extern "C" auto DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) -> NTSTATUS {
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);
	DriverObject->DriverUnload = drv_unload;
	char* targetproc = reinterpret_cast<char*>("notepad.exe");
	KAPC_STATE apc_state;
	LIST_ENTRY* le = reinterpret_cast<LIST_ENTRY*>((((unsigned char*)PsGetCurrentProcess() + offsets::eprocess_active_process_links)));
	LIST_ENTRY* le_next = le->Flink;
	PEPROCESS ep = reinterpret_cast<PEPROCESS>(le->Flink);
	unsigned char* proc = NULL;
	while (le_next != le) {
		proc = (reinterpret_cast<unsigned char*>((reinterpret_cast<unsigned char*>(ep) - offsets::eprocess_active_process_links) + offsets::eprocess_image_file_name_offset));
		if (strcmp(targetproc, reinterpret_cast<char*>(proc)) == 0) {
			bfound = true;
			break;
		}
		le_next = le_next->Flink;
		ep = (PEPROCESS)le_next->Flink;
	}
	if (bfound==true) {
		ep = reinterpret_cast<PEPROCESS>(reinterpret_cast<unsigned char*>(ep) - offsets::eprocess_active_process_links );
		KeStackAttachProcess(ep, &apc_state);
		auto pthread_list_head = PLIST_ENTRY(nullptr);
		auto pthread_list_entry = PLIST_ENTRY(nullptr);
		auto current_thread = PETHREAD(nullptr);
		
		pthread_list_head = reinterpret_cast<PLIST_ENTRY>((reinterpret_cast<unsigned char*>(ep) + offsets::eprocess_list_head_offset));
		current_thread = reinterpret_cast<PETHREAD>((reinterpret_cast<ULONG64>(pthread_list_head->Flink) - offsets::ethread_list_entry_offset));
		while (1) {
			BOOLEAN IsAlterable = *reinterpret_cast<PBOOLEAN>(reinterpret_cast<ULONG64>(current_thread) + offsets::kthread_alertable);
			if (IsAlterable==TRUE) {
				DbgPrint("found alterable thread\r\n");
				AlterableThread = current_thread;
				break;
			}
			else {
				DbgPrint("failed to get alterable thread\r\n");
			}
			pthread_list_entry = reinterpret_cast<PLIST_ENTRY>((reinterpret_cast<ULONG64>(current_thread) + offsets::ethread_list_entry_offset));
			current_thread = reinterpret_cast<PETHREAD>((reinterpret_cast<ULONG64>(pthread_list_entry->Flink) - offsets::ethread_list_entry_offset));

		}
		KeUnstackDetachProcess(&apc_state);
	}
	else {
		DbgPrint("failed to find process within ActiveProcessLinks");
	}

	return STATUS_SUCCESS;
}