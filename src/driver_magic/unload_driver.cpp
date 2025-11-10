#include "dm.h"
#include "Glibc.h"

BOOL DM_UnloadDriver(const char* drv_name)
{
    char* c_driver_full_path;
    UNICODE_STRING ServiceNameUcs;
    PWCHAR ServiceName;
    NTSTATUS retCode;
    _C_RtlInitUnicodeString InitUnicode;
    _C_NtUnloadDriver UnloadDriver;
    HMODULE hNtdll = LoadLibraryA(XorStr("ntdll.dll\0"));

    // Build the full service name
    c_driver_full_path = (char*)malloc(strlen(drv_name) + 60 + 1);
    memset(c_driver_full_path, 0, strlen(drv_name) + 60 + 1);
    drunk_strcpy(c_driver_full_path, XorStr("\\registry\\machine\\SYSTEM\\CurrentControlSet\\Services\\"));
    drunk_strcat(c_driver_full_path, drv_name);

    // Convert to wide char string
    ServiceName = drunk_cstring_to_wchar(c_driver_full_path);
    UnloadDriver = (_C_NtUnloadDriver)(void*)GetProcAddress(hNtdll, XorStr("NtUnloadDriver"));
    InitUnicode = (_C_RtlInitUnicodeString)(void*)GetProcAddress(hNtdll, XorStr("RtlInitUnicodeString"));

    // Actually unload the driver
    InitUnicode(&ServiceNameUcs, ServiceName);
    retCode = UnloadDriver(ServiceNameUcs);
    if (!NT_SUCCESS(retCode)) {
        printf("[!] Failed to stop service with error=%llx (S)\n", retCode);
    }
    else {
        printf("[+] Service %s successfully stopped !\n", drv_name);
    }
    memset(c_driver_full_path, 0, strlen(drv_name) + 60 + 1);
    free(c_driver_full_path);
    return (NT_SUCCESS(retCode));
}

