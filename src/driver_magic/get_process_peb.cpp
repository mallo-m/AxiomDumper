#include <stdio.h>
#include "AxiomDumper.h"
#include "dm.h"
#include "dm_kernelsyscall.hpp"
#include "dm_structs.h"

ULONGLONG DM_GetProcessPEB(ULONG pid)
{
	ULONGLONG peb = 0x00;
	char ntoskrnl_version_buffer[1024];

	// Get kernel version
	DM_GetKrnlVersion(ntoskrnl_version_buffer, sizeof(ntoskrnl_version_buffer), XorStr("C:\\Windows\\System32\\ntoskrnl.exe"));

	const auto ntoskrnl_base = DM_FindNtoskrnlBaseAddress();
	const auto ntoskrnl_pslookupprocessbyid = DM_GetKernelExportAddress(ntoskrnl_base, ntoskrnl_version_buffer, KE_PsLookupProcessByProcessId);
	const auto ntoskrnl_psgetprocesspeb = DM_GetKernelExportAddress(ntoskrnl_base, ntoskrnl_version_buffer, KE_PsGetProcessPeb);

	PEPROCESS pEprocess = NULL;
	DM_KernelSyscall<decltype(&KD_PsLookupProcessByProcessId)>(
		ntoskrnl_pslookupprocessbyid,
		((HANDLE)(ULONG_PTR)(pid)),
		&pEprocess
	);

	peb = (ULONGLONG)DM_KernelSyscall<decltype(&KD_PsGetProcessPeb)>(
		ntoskrnl_psgetprocesspeb,
		pEprocess
	);

	return (peb);
}

