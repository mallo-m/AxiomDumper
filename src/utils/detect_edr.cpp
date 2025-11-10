#include "utils.h"
#include "compiletime_md5.hpp"
#include "autoxor.h"
#include <psapi.h>

EdrProfile UTILS_DetectEdr()
{
	DWORD aProcesses[2048];
	DWORD cbNeeded;
	DWORD cProcesses;
	constexpr EDR_PROFILE_DISPATCHER edrDispatcher[] = {
		// Sentinel ONE
		{ compiletime_md5("SentinelUI.exe"), EdrSentinelOne },
		{ compiletime_md5("SentinelMemoryScanner.exe"), EdrSentinelOne },
		{ compiletime_md5("SentinelStaticEngine.exe"), EdrSentinelOne },
		{ compiletime_md5("SentinelServiceHost.exe"), EdrSentinelOne },
		{ compiletime_md5("SentinelStaticEngineScanner.exe"), EdrSentinelOne },
		{ compiletime_md5("SentinelAgentWorker.exe"), EdrSentinelOne },
		{ compiletime_md5("SentinelAgent.exe"), EdrSentinelOne },

		// Microsoft Defender for Endpoint, it conflicts with some Defender AV, needs another to fingerprint the presence of MDE
		//{ compiletime_md5("MsMpEng.exe"), EdrMDE },
		//{ compiletime_md5("MpDefenderCoreService.exe"), EdrMDE },

		// Kaspersky
		{ compiletime_md5("avp.exe"), EdrKaspersky },
		{ compiletime_md5("avpui.exe"), EdrKaspersky },
		{ compiletime_md5("avpsus.exe"), EdrKaspersky },
		{ compiletime_md5("kescli.exe"), EdrKaspersky },
		{ compiletime_md5("klnagent.exe"), EdrKaspersky },
		{ compiletime_md5("ksnproxy.exe"), EdrKaspersky },

		// Harfang Lab
		{ compiletime_md5("hurukai.exe"), EdrHarfang },
		{ compiletime_md5("hurukai-ui.exe"), EdrHarfang },

		// Crowdstrike
		{ compiletime_md5("CSFalconContainer.exe"), EdrCrowdstrike },
		{ compiletime_md5("CSFalconService.exe"), EdrCrowdstrike },

		// Cortex XDR
		{ compiletime_md5("cysandbox.exe"), EdrCortex },
		{ compiletime_md5("cyserver.exe"), EdrCortex },
		{ compiletime_md5("cytray.exe"), EdrCortex },
		{ compiletime_md5("cywscsvc.exe"), EdrCortex },
		{ compiletime_md5("cortex-xdr-payload.exe"), EdrCortex },
		{ compiletime_md5("cyuserserver.exe"), EdrCortex }
	};

	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
	{
		printf("[!] EnumProcesses() failed\n", -1);
		return (EdrNone);
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
			uint64_t pnameHash = compiletime_md5(filename);
			for (size_t hashi = 0; hashi < (sizeof(edrDispatcher) / sizeof(edrDispatcher[0])); hashi++)
			{
				if (pnameHash == edrDispatcher[hashi].processHash)
				{
					// Yes this is horrible code and absoletely un-optimized shit
					// But I can't afford to store those strings in clear in the binary, so...
					printf("[+] EDR detected! Adapting profile to: ");
					switch (edrDispatcher[hashi].edrProfile)
					{
						case EdrNone:
							printf("NO EDR/Defender AV\n");
							break;
						case EdrMDE:
							printf("Microsoft Defender for Endpoint\n");
							break;
						case EdrSentinelOne:
							printf("Sentinel ONE\n");
							break;
						case EdrCortex:
							printf("Cortex XDR\n");
							break;
						case EdrHarfang:
							printf("HarfangLab\n");
							break;
						case EdrCrowdstrike:
							printf("Crowdstrike Falcon\n");
							break;
						case EdrKaspersky:
							printf("Kaspersky EDR\n");
							break;
						default:
							printf("(unknown)\n");
							break;
					}
					CloseHandle(handle);
					return (edrDispatcher[hashi].edrProfile);
				}
			}

			CloseHandle(handle);
		}
	}
	printf("[+] Target is not protected by any EDR\n");
	return (EdrNone);
}

