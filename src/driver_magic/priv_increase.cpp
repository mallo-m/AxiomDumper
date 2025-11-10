#include "dm.h"
#include "dm_structs.h"

void DM_PrivIncrease()
{
    LUID luid = { 0,0 };
    LookupPrivilegeValueW(NULL, L"SeLoadDriverPrivilege", &luid);

    ULONG SE_PRIVILEGE = luid.LowPart;
    BOOLEAN PrivWasEnabled;
    _C_RtlAdjustPrivilege AdustPrivs;
    HMODULE hNtdll = LoadLibraryA(XorStr("ntdll.dll\0"));
    AdustPrivs = (_C_RtlAdjustPrivilege)(void*)GetProcAddress(hNtdll, XorStr("RtlAdjustPrivilege"));
    AdustPrivs(
        SE_PRIVILEGE,
        true,
        false,
        &PrivWasEnabled
    );
}

