#include <ntifs.h>
static UNICODE_STRING device_name = RTL_CONSTANT_STRING(L"\\Device\\ghost_injector");
static UNICODE_STRING symbolic_link = RTL_CONSTANT_STRING(L"\\DosDevices\\ghost_injector");
namespace common {
	inline bool status(NTSTATUS status) { return NT_SUCCESS(status); }

	inline PVOID api(UNICODE_STRING api_func) { return MmGetSystemRoutineAddress(&api_func); }


}
typedef NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(__in PEPROCESS Process);

PsGetProcessSectionBaseAddress* pGetProcessSectionBaseAddress;


typedef struct kghost {
	PVOID VA;
}kghost, * pkghost;

static UNICODE_STRING PsGetProcessBaseAddressApi = RTL_CONSTANT_STRING(L"PsGetProcessSectionBaseAddress");
#define KGHOST_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN,0x601,METHOD_NEITHER,FILE_READ_DATA | FILE_WRITE_DATA)
typedef struct kghost_mem {

	ULONG pid;
	char* alloc_buffer;
	SIZE_T alloc_size;
}kghost_mem, * pkghost_mem;
static auto kghost_alloc(ULONG pid, char* tshellcode, SIZE_T shellcode_size) -> PVOID {
	auto status = STATUS_SUCCESS;
	auto e_process = PEPROCESS(nullptr);
	auto mdl = PMDL(nullptr);
	KAPC_STATE kapc_state;
	PVOID address = NULL;
	PVOID base_address = NULL;
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
		MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE);
		RtlCopyMemory(user_address, tshellcode, shellcode_size);
		MmUnmapLockedPages(address, mdl);
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
		KeUnstackDetachProcess(&kapc_state);

	done:
		return user_address;
	}
	else {
		return NULL;
	}
}
static auto major_control_function(PDEVICE_OBJECT DeviceObject, PIRP Irp) -> NTSTATUS {
	UNREFERENCED_PARAMETER(DeviceObject);
	auto result = STATUS_SUCCESS;
	auto IoStackLocation = PIO_STACK_LOCATION(nullptr);
	auto xghost_mem = pkghost_mem(nullptr);

	struct kghost xkghost;
	PVOID user_address = NULL;
	IoStackLocation = IoGetCurrentIrpStackLocation(Irp);
	if (IoStackLocation->Parameters.DeviceIoControl.InputBufferLength < sizeof(kghost_mem)) {
		result = STATUS_BUFFER_TOO_SMALL;
		goto done;
	}

	xghost_mem = reinterpret_cast<pkghost_mem>(IoStackLocation->Parameters.DeviceIoControl.Type3InputBuffer);
	if (xghost_mem == NULL)
	{
		goto done;
	}
	if (IoStackLocation->Parameters.DeviceIoControl.IoControlCode == KGHOST_MEMORY) {
		user_address = kghost_alloc(xghost_mem->pid, xghost_mem->alloc_buffer, xghost_mem->alloc_size);
		xkghost.VA = user_address;
		RtlCopyMemory((PCHAR)Irp->UserBuffer, &xkghost, sizeof(kghost));

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
	result = IoCreateDevice(DriverObject, NULL, &device_name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &device_object);
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
}