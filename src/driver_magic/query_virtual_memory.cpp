#include "dm_kernelsyscall.hpp"
#include "dm_structs.h"
#include "compiletime_md5.hpp"
#include <stdio.h>

NTSTATUS DM_QueryVirtualMemory(HANDLE hProcess, PVOID64 baseAddress, PMEMORY_BASIC_INFORMATION pmbi)
{
	NTSTATUS result = STATUS_SUCCESS;
	MEMORY_INFORMATION_CLASS mic = MemoryBasicInformation;
	/*
	static _C_ZwQueryVirtualMemory userlandQueryVirtualMemory = NULL;

	if (userlandQueryVirtualMemory == NULL)
		userlandQueryVirtualMemory = (_C_ZwQueryVirtualMemory)UTILS_GetFunctionAddress(compiletime_md5("ZwQueryVirtualMemory"));
	result = userlandQueryVirtualMemory(
		hProcess,
		baseAddress,
		mic,
		pmbi,
		sizeof(MEMORY_BASIC_INFORMATION),
		NULL
	);
	return (result);
	*/

	// I still can't get the kernel version of QueryVirtualMemory to work consistently :(
	// it unexplicably always return 0xc000004 on some versions
	// Definitely the weak spot of this implementation, if it gets detected, it will be because of this

	// Get kernel version
	char ntoskrnl_version_buffer[1024];
	DM_GetKrnlVersion(ntoskrnl_version_buffer, sizeof(ntoskrnl_version_buffer), XorStr("C:\\Windows\\System32\\ntoskrnl.exe"));

	const auto ntoskrnl_base = DM_FindNtoskrnlBaseAddress();
	const auto ntoskrnl_zwqueryvirtualmemory = DM_GetKernelExportAddress(ntoskrnl_base, ntoskrnl_version_buffer, KE_ZwQueryVirtualMemory);

	result = DM_KernelSyscall<decltype(&KD_ZwQueryVirtualMemory)>(
		ntoskrnl_zwqueryvirtualmemory,
		hProcess,
		baseAddress,
		mic,
		pmbi,
		sizeof(MEMORY_BASIC_INFORMATION),
		(PSIZE_T)NULL
	);

	return (result);
}

