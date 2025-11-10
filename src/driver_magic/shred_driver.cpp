#include "AxiomDumper.h"
#include "dm.h"
#include "drv_speedfan.h"
#include "drv_winio.h"
#include <fstream>

void DM_ShredAndDeleteDriver(AXIOM_DRIVER driver, const char* drv_name)
{
	BOOL success;
	char* buffer;
	std::ofstream _file;
	char fullpath[MAX_PATH + 1];
	SIZE_T filelen;

	switch (driver)
	{
		case DriverSpeedfan:
			filelen = SPEEDFAN_SYS_LEN;
			break;
		case DriverWinIO:
			filelen = WINIO_SYS_LEN;
			break;
		default:
			filelen = 2048;
			break;
	}
	snprintf(fullpath, sizeof(fullpath), "C:\\Windows\\System32\\drivers\\%s.sys", drv_name);
	buffer = (char*)malloc(filelen);
	memset(buffer, 0, filelen);
	_file.open(fullpath, std::ios::out | std::ios::binary | std::ios::trunc);
	_file.write((const char*)buffer, filelen);
	_file.close();
	if (buffer != NULL)
		free(buffer);
	success = DeleteFileA(fullpath);
	if (!success) {
		printf("[!] Failed to delete driver file, error = 0x%08x, you should do it manually\n", GetLastError());
	}
	else {
		printf("[+] Driver file shredded and deleted\n");
	}
	memset(fullpath, 0, sizeof(fullpath));
}

