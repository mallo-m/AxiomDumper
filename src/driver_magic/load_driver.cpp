#include "dm.h"
#include "Glibc.h"

BOOL DM_LoadDriver(const char* drv_name)
{
    char* c_driver_full_path;
    UNICODE_STRING ServiceNameUcs;
    PWCHAR ServiceName;
    NTSTATUS retCode;
    _C_RtlInitUnicodeString InitUnicode;
    _C_NtLoadDriver LoadDriver;
    HMODULE hNtdll = LoadLibraryA(XorStr("ntdll.dll\0"));

    DM_PrivIncrease();

    c_driver_full_path = (char*)malloc(strlen(drv_name) + 60 + 1);
    memset(c_driver_full_path, 0, strlen(drv_name) + 60 + 1);
    drunk_strcpy(c_driver_full_path, XorStr("\\registry\\machine\\SYSTEM\\CurrentControlSet\\Services\\"));
    drunk_strcat(c_driver_full_path, drv_name);

    ServiceName = drunk_cstring_to_wchar(c_driver_full_path);
    LoadDriver = (_C_NtLoadDriver)(void*)GetProcAddress(hNtdll, "NtLoadDriver");
    InitUnicode = (_C_RtlInitUnicodeString)(void*)GetProcAddress(hNtdll, XorStr("RtlInitUnicodeString"));

    InitUnicode(&ServiceNameUcs, ServiceName);
    retCode = LoadDriver(ServiceNameUcs);

    if (!NT_SUCCESS(retCode)) {
        printf("[!] Failed to start with error=%llx (S)\n", retCode);
    }
    else {
        printf("[+] Service %s successfully loaded !\n", drv_name);
    }
    memset(c_driver_full_path, 0, strlen(drv_name) + 60 + 1);
    free(c_driver_full_path);
    return (NT_SUCCESS(retCode));
}

