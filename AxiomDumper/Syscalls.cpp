#include "AxiomDumper.h"
#include "Typedefs.h"
#include <stdio.h>

PAXIOM_TABLE AxiomTable;

static const BOOL _ExtractFunctionSNN(void* functionAddress, int* pSSN, void** pSyscallAddr)
{
	WORD cw;
	void** ntdllAddresses;

	cw = 0;
	ntdllAddresses = (void**)malloc(sizeof(void*) * (NTDLL_JUMPS_COUNT + 1));
	if (ntdllAddresses == NULL)
		return (false);
	for (int i = 0; i < (NTDLL_JUMPS_COUNT + 1); i++)
		ntdllAddresses[i] = NULL;

	while (true)
	{
		// check if syscall, in this case we are too far
		if (*((PBYTE)functionAddress + cw) == 0x0f && *((PBYTE)functionAddress + cw + 1) == 0x05)
			return (false);

		// check if ret, in this case we are also probaly too far
		if (*((PBYTE)functionAddress + cw) == 0xc3)
			return (false);

		// First opcodes should be :
		//    MOV R10, RCX
		//    MOV RCX, <syscall>
		if (*((PBYTE)functionAddress + cw) == 0x4c
			&& *((PBYTE)functionAddress + 1 + cw) == 0x8b
			&& *((PBYTE)functionAddress + 2 + cw) == 0xd1
			&& *((PBYTE)functionAddress + 3 + cw) == 0xb8
			&& *((PBYTE)functionAddress + 6 + cw) == 0x00
			&& *((PBYTE)functionAddress + 7 + cw) == 0x00) {
			BYTE high = *((PBYTE)functionAddress + 5 + cw);
			BYTE low = *((PBYTE)functionAddress + 4 + cw);

			*pSSN = ((high << 8) | low);
			for (DWORD z = 0, x = 1; z <= SSN_RANGE; z++, x++)
			{
				if (*((PBYTE)functionAddress + cw + z) == 0x0F
					&& *((PBYTE)functionAddress + cw + x) == 0x05)
				{
					PVOID syscallAddr = ((PBYTE)functionAddress + cw + z);
					//LogString("[HEAVENS HALL] Detected syscall procedure in NTDLL at 0x%p\n", syscallAddr);
					*pSyscallAddr = syscallAddr;
					break;
				}
			}

			return (true);
		}

		cw++;
	}

	return (false);
}

BOOL AXIOM_Prepare_Syscalls()
{
	bool res;
	size_t i;
	PTEB current_teb;
	PPEB current_peb;
	PLDR_DATA_TABLE_ENTRY ldr_data_table_entry;
	PIMAGE_EXPORT_DIRECTORY image_export_directory;
	PCHAR pczFunctionName;
	PVOID pFunctionAddress;
	PDWORD pdwAddressOfFunctions;
	PDWORD pdwAddressOfNames;
	PWORD pwAddressOfNameOrdinales;

	// Get TEB address of main thread
	current_teb = RtlGetThreadEnvironmentBlock();
	// Offset some bytes to get PEB address
	current_peb = current_teb->ProcessEnvironmentBlock;

	// Retrieve LDR_DATA_TABLE_ENTRY from PEB
	// In NTDLL, this has a record of every loaded module, whoch is quite interesting to us :p
	// Credit to : https://stackoverflow.com/questions/65717594/unable-to-read-memory-on-kernel32-dll-base-address
	// Answer is wrong tho, real address is at -0x10 bytes offset, I just bruteforced it until it worked lol
	ldr_data_table_entry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)current_peb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);
	res = GetImageExportDirectory(ldr_data_table_entry->DllBase, &image_export_directory);

	// Check that all addresses loaded well
	if (res == false || image_export_directory == NULL) {
		printf("GetImageExportDirectory init failure");
		return (1);
	}

	// From the EAT, parse all functions and load syscalls metadata
	// into our internal structs
	i = 0;
	pdwAddressOfFunctions = (PDWORD)((PBYTE)ldr_data_table_entry->DllBase + image_export_directory->AddressOfFunctions);
	pdwAddressOfNames = (PDWORD)((PBYTE)ldr_data_table_entry->DllBase + image_export_directory->AddressOfNames);
	pwAddressOfNameOrdinales = (PWORD)((PBYTE)ldr_data_table_entry->DllBase + image_export_directory->AddressOfNameOrdinals);
	for (WORD cx = 0; cx < image_export_directory->NumberOfNames; cx++)
	{
		pczFunctionName = (PCHAR)((PBYTE)ldr_data_table_entry->DllBase + pdwAddressOfNames[cx]);
		pFunctionAddress = (PBYTE)ldr_data_table_entry->DllBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

		int SSN = 0;
		void* syscallAddr = NULL;
		_ExtractFunctionSNN(pFunctionAddress, &SSN, &syscallAddr);
		if (SSN == 0 || syscallAddr == NULL)
		{
			if (pczFunctionName[0] == 'N' && pczFunctionName[1] == 't')
				printf("%s is potentially hooked\n", pczFunctionName);
			continue;
		}

		i++;
		PAXIOM_TABLE_ENTRY newEntry = (PAXIOM_TABLE_ENTRY)malloc(sizeof(AXIOM_TABLE_ENTRY));
		if (newEntry == NULL) {
			printf("Malloc failure on new table entry\n");
			return (false);
		}

		newEntry->pAddress = pFunctionAddress;
		newEntry->humanFriendlyName = drunk_strdup(pczFunctionName);
		newEntry->dwHash = drunk_md5(pczFunctionName);
		newEntry->wSystemCall = SSN;
		newEntry->wSystemCallAddress = syscallAddr;
		//printf("Function name at addr %p: (hash: %s) %s with SSN: %d and syscall address: 0x%p\n", pFunctionAddress, newEntry->dwHash, pczFunctionName, newEntry->wSystemCall, newEntry->wSystemCallAddress);
		AXIOM_AddToAxiomTable(newEntry);
	}
	printf("Loaded %d table entries\n", i);
	return (true);
}

//=============================================================================
//|       So basically every syscall will have its metadata stored in a       |
//|    linked-list element. Easier to manage during parsing than a growing    |
//|                                  array.                                   |
//=============================================================================

// Init linked list
BOOL AXIOM_InitAxiomTable(PAXIOM_TABLE_ENTRY newEntry)
{
	PAXIOM_TABLE current;

	AxiomTable = (PAXIOM_TABLE)malloc(sizeof(AXIOM_TABLE));
	if (AxiomTable == NULL) {
		printf("HellsTable init failure\n");
		return (false);
	}
	AxiomTable->item = newEntry;
	AxiomTable->next = NULL;

	return (true);
}

// Add element to linked list
BOOL AXIOM_AddToAxiomTable(PAXIOM_TABLE_ENTRY newEntry)
{
	PAXIOM_TABLE current;

	current = AxiomTable;
	if (current == NULL) {
		AXIOM_InitAxiomTable(newEntry);
		return (true);
	}
	while (current != NULL && current->next != NULL)
		current = current->next;
	current->next = (PAXIOM_TABLE)malloc(sizeof(AXIOM_TABLE));
	if (current->next == NULL) {
		printf("AddsToTable malloc failure\n");
		return (false);
	}
	current->next->item = newEntry;
	current->next->next = NULL;

	return (true);
}

// Search element by hash
void* AXIOM_GetSyscallAddrByHash(const char* hash)
{
	PAXIOM_TABLE current;

	current = AxiomTable;
	while (current != NULL)
	{
		if (drunk_strcmp(current->item->dwHash, hash) == 0) {
			//LogString("[SNN] Retrieved SNN %d for hash %s\n", current->item->wSystemCall, hash);
			return (current->item->wSystemCallAddress);
		}
		current = current->next;
	}
	return (NULL);
}

// Get syscall number by hash
const int AXIOM_GetSNNByHash(const char* hash)
{
	PAXIOM_TABLE current;

	current = AxiomTable;
	while (current != NULL)
	{
		if (drunk_strcmp(current->item->dwHash, hash) == 0) {
			//LogString("[SNN] Retrieved SNN %d for hash %s\n", current->item->wSystemCall, hash);
			return (current->item->wSystemCall);
		}
		current = current->next;
	}
	return (-1);
}
