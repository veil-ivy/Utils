

#include <iostream.h>
#include <ntifs.h>

//
//  build 9841 x64 structures
// 
//

#pragma warning(disable : 4214 4201)
#pragma pack(push, 1)
typedef union _EX_FAST_REF // Size=8
{
    void* Object;
    struct
    {
        unsigned __int64 RefCnt : 4;
    };
    unsigned __int64 Value;
} EX_FAST_REF, * PEX_FAST_REF;
typedef struct _CONTROL_AREA // Size=120
{
    struct _SEGMENT* Segment;
    struct _LIST_ENTRY ListHead;
    unsigned __int64 NumberOfSectionReferences;
    unsigned __int64 NumberOfPfnReferences;
    unsigned __int64 NumberOfMappedViews;
    unsigned __int64 NumberOfUserReferences;
    unsigned long f1;
    unsigned long f2;
    EX_FAST_REF FilePointer;
    // Other fields
} CONTROL_AREA, * PCONTROL_AREA;

typedef struct _SUBSECTION // Size=56
{
    PCONTROL_AREA ControlArea;
    // Other fields
} SUBSECTION, * PSUBSECTION;
typedef struct _MM_AVL_NODE // Size=24
{
    struct _MM_AVL_NODE* LeftChild; // Size=8 Offset=0
    struct _MM_AVL_NODE* RightChild; // Size=8 Offset=8

    union ___unnamed1666 // Size=8
    {
        struct
        {
            __int64 Balance : 2; // Size=8 Offset=0 BitOffset=0 BitCount=2
        };
        struct _MM_AVL_NODE* Parent; // Size=8 Offset=0
    } u1;
} MM_AVL_NODE, * PMM_AVL_NODE, * PMMADDRESS_NODE;

typedef struct _RTL_AVL_TREE // Size=8
{
    PMM_AVL_NODE BalancedRoot;
    void* NodeHint;
    unsigned __int64 NumberGenericTableElements;
} RTL_AVL_TREE, * PRTL_AVL_TREE, MM_AVL_TABLE, * PMM_AVL_TABLE;

union _EX_PUSH_LOCK // Size=8
{
    struct
    {
        unsigned __int64 Locked : 1; // Size=8 Offset=0 BitOffset=0 BitCount=1
        unsigned __int64 Waiting : 1; // Size=8 Offset=0 BitOffset=1 BitCount=1
        unsigned __int64 Waking : 1; // Size=8 Offset=0 BitOffset=2 BitCount=1
        unsigned __int64 MultipleShared : 1; // Size=8 Offset=0 BitOffset=3 BitCount=1
        unsigned __int64 Shared : 60; // Size=8 Offset=0 BitOffset=4 BitCount=60
    };
    unsigned __int64 Value; // Size=8 Offset=0
    void* Ptr; // Size=8 Offset=0
};

struct _MMVAD_FLAGS // Size=4
{
    unsigned long VadType : 3; // Size=4 Offset=0 BitOffset=0 BitCount=3
    unsigned long Protection : 5; // Size=4 Offset=0 BitOffset=3 BitCount=5
    unsigned long PreferredNode : 6; // Size=4 Offset=0 BitOffset=8 BitCount=6
    unsigned long NoChange : 1; // Size=4 Offset=0 BitOffset=14 BitCount=1
    unsigned long PrivateMemory : 1; // Size=4 Offset=0 BitOffset=15 BitCount=1
    unsigned long Teb : 1; // Size=4 Offset=0 BitOffset=16 BitCount=1
    unsigned long PrivateFixup : 1; // Size=4 Offset=0 BitOffset=17 BitCount=1
    unsigned long ManySubsections : 1; // Size=4 Offset=0 BitOffset=18 BitCount=1
    unsigned long Spare : 12; // Size=4 Offset=0 BitOffset=19 BitCount=12
    unsigned long DeleteInProgress : 1; // Size=4 Offset=0 BitOffset=31 BitCount=1
};
struct _MMVAD_FLAGS1 // Size=4
{
    unsigned long CommitCharge : 31; // Size=4 Offset=0 BitOffset=0 BitCount=31
    unsigned long MemCommit : 1; // Size=4 Offset=0 BitOffset=31 BitCount=1
};

struct _MMVAD_FLAGS2 // Size=4
{
    unsigned long FileOffset : 24; // Size=4 Offset=0 BitOffset=0 BitCount=24
    unsigned long Large : 1; // Size=4 Offset=0 BitOffset=24 BitCount=1
    unsigned long TrimBehind : 1; // Size=4 Offset=0 BitOffset=25 BitCount=1
    unsigned long Inherit : 1; // Size=4 Offset=0 BitOffset=26 BitCount=1
    unsigned long CopyOnWrite : 1; // Size=4 Offset=0 BitOffset=27 BitCount=1
    unsigned long NoValidationNeeded : 1; // Size=4 Offset=0 BitOffset=28 BitCount=1
    unsigned long Spare : 3; // Size=4 Offset=0 BitOffset=29 BitCount=3
};

struct _MI_VAD_SEQUENTIAL_INFO // Size=8
{
    unsigned __int64 Length : 12; // Size=8 Offset=0 BitOffset=0 BitCount=12
    unsigned __int64 Vpn : 52; // Size=8 Offset=0 BitOffset=12 BitCount=52
};

union ___unnamed1951 // Size=4
{
    unsigned long LongFlags; // Size=4 Offset=0
    struct _MMVAD_FLAGS VadFlags; // Size=4 Offset=0
};

union ___unnamed1952 // Size=4
{
    unsigned long LongFlags1; // Size=4 Offset=0
    struct _MMVAD_FLAGS1 VadFlags1; // Size=4 Offset=0
};

union ___unnamed2047 // Size=4
{
    unsigned long LongFlags2; // Size=4 Offset=0
    struct _MMVAD_FLAGS2 VadFlags2; // Size=4 Offset=0
};

union ___unnamed2048 // Size=8
{
    struct _MI_VAD_SEQUENTIAL_INFO SequentialVa; // Size=8 Offset=0
    struct _MMEXTEND_INFO* ExtendedInfo; // Size=8 Offset=0
};

typedef struct _MMVAD_SHORT // Size=64
{
    union
    {
        struct _RTL_BALANCED_NODE VadNode; // Size=24 Offset=0
        struct _MMVAD_SHORT* NextVad; // Size=8 Offset=0
    };
    unsigned long StartingVpn; // Size=4 Offset=24
    unsigned long EndingVpn; // Size=4 Offset=28
    unsigned char StartingVpnHigh; // Size=1 Offset=32
    unsigned char EndingVpnHigh; // Size=1 Offset=33
    unsigned char CommitChargeHigh; // Size=1 Offset=34
    unsigned char SpareNT64VadUChar; // Size=1 Offset=35
    long ReferenceCount; // Size=4 Offset=36
    union _EX_PUSH_LOCK PushLock; // Size=8 Offset=40
    union ___unnamed1951 u; // Size=4 Offset=48
    union ___unnamed1952 u1; // Size=4 Offset=52
    struct _MI_VAD_EVENT_BLOCK* EventList; // Size=8 Offset=56
} MMVAD_SHORT, * PMMVAD_SHORT;


typedef struct _MMVAD // Size=128
{
    struct _MMVAD_SHORT Core; // Size=64 Offset=0
    union ___unnamed2047 u2; // Size=4 Offset=64
    unsigned long pad0;  // Size=4 Offset=68
    struct _SUBSECTION* Subsection; // Size=8 Offset=72
    struct _MMPTE* FirstPrototypePte; // Size=8 Offset=80
    struct _MMPTE* LastContiguousPte; // Size=8 Offset=88
    struct _LIST_ENTRY ViewLinks; // Size=16 Offset=96
    struct _EPROCESS* VadsProcess; // Size=8 Offset=112
    union ___unnamed2048 u4; // Size=8 Offset=120
    struct _FILE_OBJECT* FileObject; // Size=8 Offset=128
} MMVAD, * PMMVAD;
#pragma pack(pop)

typedef struct _HANDLE_TABLE
{
    ULONG NextHandleNeedingPool;
    long ExtraInfoPages;
    LONG_PTR TableCode;
    PEPROCESS QuotaProcess;
    LIST_ENTRY HandleTableList;
    ULONG UniqueProcessId;
    ULONG Flags;
    EX_PUSH_LOCK HandleContentionEvent;
    EX_PUSH_LOCK HandleTableLock;
    // More fields here...
} HANDLE_TABLE, * PHANDLE_TABLE;

typedef struct _API_SET_VALUE_ENTRY_10
{
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG ValueOffset;
    ULONG ValueLength;
} API_SET_VALUE_ENTRY_10, * PAPI_SET_VALUE_ENTRY_10;

typedef struct _API_SET_VALUE_ARRAY_10
{
    ULONG Flags;
    ULONG NameOffset;
    ULONG Unk;
    ULONG NameLength;
    ULONG DataOffset;
    ULONG Count;
} API_SET_VALUE_ARRAY_10, * PAPI_SET_VALUE_ARRAY_10;

typedef struct _API_SET_NAMESPACE_ENTRY_10
{
    ULONG Limit;
    ULONG Size;
} API_SET_NAMESPACE_ENTRY_10, * PAPI_SET_NAMESPACE_ENTRY_10;

typedef struct _API_SET_NAMESPACE_ARRAY_10
{
    ULONG Version;
    ULONG Size;
    ULONG Flags;
    ULONG Count;
    ULONG Start;
    ULONG End;
    ULONG Unk[2];
} API_SET_NAMESPACE_ARRAY_10, * PAPI_SET_NAMESPACE_ARRAY_10;

#pragma warning(default : 4214 4201)

static UNICODE_STRING device_name = RTL_CONSTANT_STRING(L"\\Device\\VadWalkr");
static UNICODE_STRING symbolic_link = RTL_CONSTANT_STRING(L"\\DosDevices\\VadWalkr");
#define VADWALK_IOCTL_PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x501, METHOD_NEITHER,FILE_READ_DATA | FILE_WRITE_DATA)

const ULONG vadroot_offset = 0x7d8;
typedef struct mem {
    ULONG pid;
}mem,*pmem;

static auto display_info(PMMVAD vad)->void {
    auto result = STATUS_SUCCESS;
    __try {
        if (vad->Subsection != NULL) {
            if (vad->Subsection->ControlArea != NULL) {
                if (vad->Subsection->ControlArea->FilePointer.Object != NULL) {
                    PFILE_OBJECT file_object = reinterpret_cast<PFILE_OBJECT>((vad->Subsection->ControlArea->FilePointer.Value & ~0xF));
              
                    DbgPrint("fileobject->filename: %ws\r\n", file_object->FileName.Buffer); 
                 
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        result = STATUS_ACCESS_VIOLATION;
        DbgPrint("error accessing buffer: %X", result);

    }
    return;


}
static auto query_vads(PMM_AVL_TABLE ptable) -> void {
    auto left_child = PMMVAD(nullptr);
    auto right_child = PMMVAD(nullptr);
    auto result = STATUS_SUCCESS;
    __try {


        left_child = reinterpret_cast<PMMVAD>(ptable->BalancedRoot->LeftChild);
        right_child = reinterpret_cast<PMMVAD>(ptable->BalancedRoot->RightChild);
        while (left_child->Core.NextVad != 0) {
            DbgPrint("NextVad => %p\r\n", left_child->Core.NextVad);
            display_info(left_child);
           
            left_child = reinterpret_cast<PMMVAD>(left_child->Core.NextVad);
        }
        while (right_child->Core.NextVad != 0) {
            DbgPrint("NextVad => %p\r\n", right_child->Core.NextVad);
            display_info(right_child);
            right_child = reinterpret_cast<PMMVAD>(right_child->Core.NextVad);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        result = STATUS_ACCESS_VIOLATION;
        DbgPrint("error accessing buffer :%X", result);
      
    }
    return;
}
static auto walk_avl_tree(ULONG pid)->void {

    auto result = STATUS_SUCCESS;
    auto ep = PEPROCESS(NULL);
    result = PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(pid), &ep);
    if (!NT_SUCCESS(result)) {
        DbgPrint("failed to get eprocess error :%X", result);
        goto done;
    }
    PMM_AVL_TABLE ptable = reinterpret_cast<PMM_AVL_TABLE>((reinterpret_cast<unsigned char *>(ep) + vadroot_offset));
    
    query_vads(ptable);
done:
    return;
}

static auto major_control_function(PDEVICE_OBJECT DeviceObject, PIRP Irp) -> NTSTATUS {
    UNREFERENCED_PARAMETER(DeviceObject);
    auto result = STATUS_SUCCESS;
    auto IoStackLocation = PIO_STACK_LOCATION(nullptr);
    auto xmem = pmem(nullptr);
    IoStackLocation = IoGetCurrentIrpStackLocation(Irp);
    if (IoStackLocation->Parameters.DeviceIoControl.InputBufferLength < sizeof(struct mem)) {
        result = STATUS_BUFFER_TOO_SMALL;
        DbgPrint("invalid data : %X\r\n", result);
        goto done;
    }
  
    xmem = reinterpret_cast<pmem>(IoStackLocation->Parameters.DeviceIoControl.Type3InputBuffer);
    if (xmem == NULL) {
        DbgPrint("failed\r\n");
        goto done;
    }
    if (IoStackLocation->Parameters.DeviceIoControl.IoControlCode == VADWALK_IOCTL_PID) {
        walk_avl_tree(xmem->pid);
    }
    else {
    
        result = STATUS_NOT_SUPPORTED;
        DbgPrint("invalid IOCTL %X", result);
        
    }
done:
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return result;
}

static auto default_major_function(PDEVICE_OBJECT DeviceObject,PIRP Irp) -> NTSTATUS {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_NOT_SUPPORTED;
}
static auto unload(PDRIVER_OBJECT DriverObject)-> void {
    IoDeleteSymbolicLink(&symbolic_link);
    IoDeleteDevice(DriverObject->DeviceObject);

}
extern "C" auto DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) -> NTSTATUS {
    UNREFERENCED_PARAMETER(RegistryPath);
    static auto result = STATUS_SUCCESS;
    static auto device_object = PDEVICE_OBJECT(nullptr);
    
    DriverObject->DriverUnload = unload;
    for (auto i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
        DriverObject->MajorFunction[i] = default_major_function;
    }
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = major_control_function;
    result = IoCreateDevice(DriverObject, NULL, &device_name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &device_object);
    if (!NT_SUCCESS(result)) {
        DbgPrint("failed to create device error : %X\n",result);
        return result;
    }
    
    result = IoCreateSymbolicLink(&symbolic_link, &device_name);
    if (!NT_SUCCESS(result)) {
        DbgPrint("failed to create symbolic link error :%X\n", result);
        IoDeleteDevice(device_object);
        return result;
    }
    return result;

}


