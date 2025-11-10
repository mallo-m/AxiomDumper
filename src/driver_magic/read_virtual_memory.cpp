#include "AxiomDumper.h"
#include "autoxor.h"
#include "dm.h"
#include "dm_kernelsyscall.hpp"
#include "dm_structs.h"
#include <stdio.h>

void DM_ReadVirtualMemory(HANDLE hProcess, ULONGLONG targetAddress, PVOID buffer, SIZE_T size)
{
	char ntoskrnl_version_buffer[1024];

	// Get kernel version
	DM_GetKrnlVersion(ntoskrnl_version_buffer, sizeof(ntoskrnl_version_buffer), XorStr("C:\\Windows\\System32\\ntoskrnl.exe"));

	const auto ntoskrnl_base = DM_FindNtoskrnlBaseAddress();
	const auto ntoskrnl_zwreadvirtualmemory = DM_GetKernelExportAddress(ntoskrnl_base, ntoskrnl_version_buffer, KE_ZwReadVirtualMemory);

	DM_KernelSyscall<decltype(&KD_ZwReadVirtualMemory)>(
		ntoskrnl_zwreadvirtualmemory,
		hProcess,
		(PVOID)targetAddress,
		buffer,
		size,
		(PSIZE_T)NULL
	);
}

