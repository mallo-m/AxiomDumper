#include "Glibc.h"
#include <string>

const char* drunk_wchar_to_cstring(wchar_t* source)
{
	char* result;
	const char* rtmp;
	std::wstring wtmp;
	std::string stmp;

	wtmp = std::wstring(source);
	stmp = std::string(wtmp.begin(), wtmp.end());
	rtmp = stmp.c_str();
	result = (char*)malloc(sizeof(char) * strlen(rtmp) + 1);
	if (result == NULL)
	return (NULL);
		drunk_strcpy(result, rtmp);
	return (result);
}

