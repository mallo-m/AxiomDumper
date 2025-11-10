#include "dm.h"
#include "drv_speedfan.h"
#include "drv_winio.h"
#include <fstream>

void DM_DropDriverToDisk(AXIOM_DRIVER driver, const char* drv_name)
{
	std::ofstream _file;
	char fullpath[MAX_PATH + 1];

	snprintf(fullpath, sizeof(fullpath), "C:\\Windows\\System32\\drivers\\%s.sys", drv_name);
	_file.open(fullpath, std::ios::out | std::ios::binary | std::ios::trunc);
	switch (driver)
	{
		case DriverSpeedfan:
			_file.write((const char*)speedfan_sys, SPEEDFAN_SYS_LEN);
			break;
		case DriverWinIO:
			_file.write((const char*)winio_sys, WINIO_SYS_LEN);
			break;
		default:
			printf("[!] Unknown driver type upon droping file, this shouldn't happen\n");
			break;
	}

	_file.close();
	memset(fullpath, 0, sizeof(fullpath));
}

