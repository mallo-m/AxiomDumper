#ifndef UTILS_H
# define UTILS_H

# include <windows.h>
# include <stdint.h>

enum EdrProfile
{
	EdrNone = 0,
	EdrSentinelOne = 1,
	EdrMDE = 2,
	EdrKaspersky = 3,
	EdrHarfang = 4,
	EdrCrowdstrike = 5,
	EdrCortex = 6
};

typedef struct _EDR_PROFILE_DISPATCHER
{
	ULONGLONG processHash;
	EdrProfile edrProfile;
} EDR_PROFILE_DISPATCHER;

BOOL UTILS_PrivCheck();
int UTILS_NetworkEmitter(const char* ip, int port, unsigned char* buffer, size_t bufferSize);
EdrProfile UTILS_DetectEdr();
ULONGLONG UTILS_GetFunctionAddress(uint64_t functionNameHash);

#endif
