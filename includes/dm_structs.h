#ifndef DM_STRUCTS_H
# define DM_STRUCTS_H

# include "Typedefs.h"

typedef struct _OS_OFFSET
{
    const uint64_t version;
    const ULONGLONG zwclose;
    const ULONGLONG zwopenprocess;
    const ULONGLONG pslookupprocess;
    const ULONGLONG zwduplicateobject;
    const ULONGLONG ntshutdownsystem;
    const ULONGLONG psgetprocesspeb;
    const ULONGLONG memcpy;
    const ULONGLONG mmcopymemory;
    const ULONGLONG mmmapiospace;
    const ULONGLONG zwreadvirtualmemory;
    const ULONGLONG zwqueryvirtualmemory;
    const ULONGLONG miqueryaddressstate;
} OS_OFFSET, * POS_OFFSET;

# define KE_ZwClose 0x01
# define KE_ZwOpenProcess 0x02
# define KE_PsLookupProcessByProcessId 0x04
# define KE_ZwDuplicateObject 0x08
# define KE_NtShutdownSystem 0x10
# define KE_PsGetProcessPeb 0x20
# define KE_memcpy 0x40
# define KE_MmCopyMemory 0x80
# define KE_MmMapIoSpace 0x100
# define KE_ZwReadVirtualMemory 0x200
# define KE_ZwQueryVirtualMemory 0x400
# define KE_MiQueryAddressState 0x0800

# define MM_COPY_MEMORY_PHYSICAL            0x1
# define MM_COPY_MEMORY_VIRTUAL             0x2
# define PAGE_OFFSET_SIZE                   12

typedef struct __C_CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} C_CLIENT_ID, * PC_CLIENT_ID;
enum KPROCESSOR_MODE {
    KernelMode,
    UserMode,
    MaximumMode
};
typedef struct _KAPC_STATE
{
    LIST_ENTRY ApcListHead[MaximumMode];
    struct _KPROCESS* Process;
    BOOLEAN KernelApcInProgress;
    BOOLEAN KernelApcPending;
    BOOLEAN UserApcPending;
} KAPC_STATE, * PKAPC_STATE, * PRKAPC_STATE;

typedef struct _MM_COPY_ADDRESS {
    union {
        PVOID            VirtualAddress;
        LARGE_INTEGER   PhysicalAddress;
    };
} MM_COPY_ADDRESS, * PMMCOPY_ADDRESS;

typedef enum _MEMORY_CACHING_TYPE {
    MmNonCached,
    MmCached,
    MmWriteCombined,
    MmHardwareCoherentCached,
    MmNonCachedUnordered,
    MmUSWCCached,
    MmMaximumCacheType,
    MmNotMapped
} MEMORY_CACHING_TYPE;

typedef enum _MEMORY_INFORMATION_CLASS
{
    MemoryBasicInformation,
    MemoryWorkingSetInformation,
    MemoryMappedFilenameInformation,
    MemoryRegionInformation,
    MemoryWorkingSetExInformation,
    MemorySharedCommitInformation,
    MemoryImageInformation,
    MemoryRegionInformationEx,
    MemoryPrivilegedBasicInformation,
    MemoryEnclaveImageInformation,
    MemoryBasicInformationCapped
} MEMORY_INFORMATION_CLASS, * PMEMORY_INFORMATION_CLASS;

NTSYSAPI NTSTATUS KD_ZwOpenProcess(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PC_CLIENT_ID       ClientId
);
NTSYSAPI NTSTATUS KD_ZwClose(
    HANDLE Handle
);
NTSYSAPI NTSTATUS KD_ZwDuplicateObject(
    HANDLE      SourceProcessHandle,
    HANDLE      SourceHandle,
    HANDLE      TargetProcessHandle,
    PHANDLE     TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG       HandleAttributes,
    ULONG       Options
);

NTSYSAPI NTSTATUS KD_ZwReadVirtualMemory(
    IN  HANDLE  	ProcessHandle,
    IN  PVOID  	    BaseAddress,
    IN  PVOID  	    Buffer,
    IN  SIZE_T  	NumberOfBytesToRead,
    OUT PSIZE_T  	NumberOfBytesRead
);

NTSYSAPI NTSTATUS KD_PsLookupProcessByProcessId(
    HANDLE    ProcessId,
    PEPROCESS* Process
);
NTSYSAPI NTSTATUS KD_KeStackAttachProcess(
    PEPROCESS   PROCESS,
    PKAPC_STATE ApcState
);

NTSYSAPI PPEB KD_PsGetProcessPeb(
    IN PEPROCESS Process
);

NTSYSAPI NTSTATUS KD_MmCopyVirtualMemory(
    IN PEPROCESS        SourceProcess,
    IN PVOID            SourceAddress,
    IN PEPROCESS        TargetProcess,
    OUT PVOID           TargetAddress,
    IN SIZE_T           BufferSize,
    IN KPROCESSOR_MODE  PreviousMode,
    OUT PSIZE_T  	    ReturnSize
);

NTSYSAPI NTSTATUS KD_MmCopyMemory(
    IN  PVOID           TargetAddress,
    IN  ULONGLONG       SourceAddress,
    IN  SIZE_T          NumberOfBytes,
    IN  ULONG           Flags,
    OUT PSIZE_T         NumberOfBytesTransferred
);

NTSYSAPI PVOID KD_MmMapIoSpace(
    IN ULONGLONG           PhysicalAddress,
    IN SIZE_T              NumberOfBytes,
    IN MEMORY_CACHING_TYPE CacheType
);

NTSYSAPI NTSTATUS KD_ZwQueryVirtualMemory(
    IN  HANDLE                   ProcessHandle,
    IN  PVOID                    BaseAddress,
    IN	MEMORY_INFORMATION_CLASS MemoryInformationClass,
    OUT PVOID                    MemoryInformation,
    IN  SIZE_T                   MemoryInformationLength,
    OUT PSIZE_T                  ReturnLength
);

NTSYSAPI ULONG KD_MiQueryAddressState(
    IN PVOID Va,
    IN PVOID Vad,
    IN PEPROCESS TargetProcess,
    OUT PULONG ReturnedProtect,
    OUT PVOID* NextVaToQuery
);

typedef int(NTAPI* _C_RtlAdjustPrivilege)(
    _In_ ULONG Privilege,
    _In_ BOOLEAN Enable,
    _In_ BOOLEAN Client,
    _Out_ PBOOLEAN WasEnabled
    );

typedef VOID(NTAPI* _C_RtlInitUnicodeString)(
    OUT PUNICODE_STRING DestinationString,
    IN PCWSTR SourceString
    );

typedef NTSTATUS(NTAPI* _C_NtLoadDriver)(
    IN UNICODE_STRING DriverServiceName
    );

typedef NTSTATUS(NTAPI* _C_NtUnloadDriver)(
    IN UNICODE_STRING DriverServiceName
    );

typedef int(NTAPI* _C_RtlCreateRegistryKey)(
    _In_ ULONG RelativeTo,
    _In_ PWSTR Path
    );

typedef int(NTAPI* _C_RtlWriteRegistryValue)(
    _In_ ULONG RelativeTo,
    _In_ PCWSTR Path,
    _In_ PCWSTR ValueName,
    _In_ ULONG ValueType,
    _In_opt_ PVOID ValueData,
    _In_ ULONG ValueLength
    );

typedef NTSTATUS(NTAPI* _C_ZwQueryVirtualMemory)(
    IN  HANDLE                   ProcessHandle,
    IN  PVOID64                  BaseAddress,
    IN	MEMORY_INFORMATION_CLASS MemoryInformationClass,
    OUT PVOID                    MemoryInformation,
    IN  SIZE_T                   MemoryInformationLength,
    OUT PSIZE_T                  ReturnLength
    );

#endif
