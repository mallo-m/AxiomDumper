#include "utils.h"
#include "autoxor.h"
#include "compiletime_md5.hpp"
#include "Typedefs.h"

//https://learn.microsoft.com/fr-fr/windows/win32/api/winternl/ns-winternl-teb
//Pointer to TEB of current thread (in this case the main one duh)
//This struct describes the state of a thread
//We will later simply offset from TEB's address to get PEB's one
static PTEB RtlGetThreadEnvironmentBlock()
{
	return (PTEB)__readgsqword(0x30);
}

//Used to get _IMAGE_EXPORT_DIR of ntdll.dll
//The EXPORT_DIR of a module contains all exported functions names along with
//their RVA (Relative Virual Address) -> the juicy part (SSN babyyyyy)
static BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory)
{
	// Get DOS header
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return FALSE;
	}

	// Get NT headers
	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDosHeader->e_lfanew);
	if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}

	// Get the EAT
	*ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
	return (TRUE);
}

ULONGLONG UTILS_GetFunctionAddress(uint64_t functionNameHash)
{
	WORD cx;
	ULONGLONG result;
	PTEB current_teb;
	PPEB current_peb;
	PCHAR pczFunctionName;
	PVOID pFunctionAddress;
	uint64_t hash;
	static PLDR_DATA_TABLE_ENTRY ldr_data_table_entry = NULL;
	static PIMAGE_EXPORT_DIRECTORY image_export_directory = NULL;
	static PDWORD pdwAddressOfFunctions = NULL;
	static PDWORD pdwAddressOfNames = NULL;
	static PWORD pwAddressOfNameOrdinales = NULL;

	result = 0x00;
	if (ldr_data_table_entry == NULL || image_export_directory == NULL)
	{
		// Get TEB address of main thread
		current_teb = RtlGetThreadEnvironmentBlock();
		// Offset some bytes to get PEB address
		current_peb = current_teb->ProcessEnvironmentBlock;

		// Retrieve LDR_DATA_TABLE_ENTRY from PEB
		// In NTDLL, this has a record of every loaded module, whoch is quite interesting to us :p
		// Credit to : https://stackoverflow.com/questions/65717594/unable-to-read-memory-on-kernel32-dll-base-address
		// Answer is wrong tho, real address is at -0x10 bytes offset, I just bruteforced it until it worked lol
		ldr_data_table_entry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)current_peb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);
		GetImageExportDirectory(ldr_data_table_entry->DllBase, &image_export_directory);

		pdwAddressOfFunctions = (PDWORD)((PBYTE)ldr_data_table_entry->DllBase + image_export_directory->AddressOfFunctions);
		pdwAddressOfNames = (PDWORD)((PBYTE)ldr_data_table_entry->DllBase + image_export_directory->AddressOfNames);
		pwAddressOfNameOrdinales = (PWORD)((PBYTE)ldr_data_table_entry->DllBase + image_export_directory->AddressOfNameOrdinals);
	}

	//printf("[+] Extrapolated ntdll address: 0x%llx\n", ldr_data_table_entry->DllBase);
	for (cx = 0; cx < image_export_directory->NumberOfNames; cx++)
	{
		pczFunctionName = (PCHAR)((PBYTE)ldr_data_table_entry->DllBase + pdwAddressOfNames[cx]);
		pFunctionAddress = (PBYTE)ldr_data_table_entry->DllBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];
		hash = compiletime_md5(pczFunctionName);
		if (hash == functionNameHash)
		{
			//printf("[+] Function %s located at 0x%llx\n", pczFunctionName, pFunctionAddress);
			result = (ULONGLONG)pFunctionAddress;
			break;
		}
	}

	return (result);
}

