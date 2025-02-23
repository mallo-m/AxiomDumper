#include <stdio.h>

#include "AxiomDumper.h"
#include "SSN.h"
#include "SSN_Hashes.h"

void AXIOM_PPcheck(char* process_id)
{
	DWORD proc_id;
	HANDLE process_handle;
	PVOID processInfoBuffer;
	NTSTATUS status;
	BYTE protect;
	char* result;
	char* proc_name;

	const char* signers[] = {
		"SignerNone",
		"SignerAuthenticode",
		"SignerCodeGen",
		"SignerAntimalware",
		"SignerLsa",
		"SignerWindows",
		"SignerWinTcb",
		"SignerWinSystem",
		"SignerApp",
		"SignerMax"
	};
	const char* types[] = {
		"TypeNone",
		"TypeProtectedLight",
		"TypeProtected",
	};

	proc_id = drunk_atoi(process_id);
	process_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, proc_id);
	processInfoBuffer = malloc(2048);
	IndirectSyscall(
		status,
		AXIOM_SSN_NtQueryInformationProcess,
		process_handle,
		61UL,
		&protect,
		1,
		NULL
	);
	IndirectSyscall(
		status,
		AXIOM_SSN_NtQueryInformationProcess,
		process_handle,
		27,
		processInfoBuffer,
		2048,
		NULL
	);

	result = (char*)malloc(2048);
	proc_name = (char*)drunk_wchar_to_cstring(((PUNICODE_STRING)processInfoBuffer)->Buffer);
	memset(result, 0, 2048);
	printf(
		"Protection status for process: %d (%s)\n\n\tType:\tPsProtected%s\n\tSigner:\tPsProtected%s\n\n",
		proc_id,
		proc_name,
		types[protect & 0b111],
		signers[(protect & 0b11110000) >> 4]
	);

	free(proc_name);
	free(processInfoBuffer);
	CloseHandle(process_handle);
}
