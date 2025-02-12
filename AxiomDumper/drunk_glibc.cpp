#include "AxiomDumper.h"
#include <string>

const char* drunk_strcpy(char* dest, const char* src)
{
	int i;

	i = 0;
	while (src[i] != '\0')
	{
		dest[i] = src[i];
		i++;
	}
	dest[i] = '\0';
	return (dest);
}

const char* drunk_strdup(const char* str)
{
	char* res;
	char* cursor;

	if (str == (NULL))
		return (NULL);
	cursor = res = (char*)malloc(sizeof(char) + strlen(str) + 1);
	if (cursor == NULL)
		return (NULL);
	while (*str != '\0')
		*cursor++ = *str++;
	*cursor = '\0';
	return (res);
}

const int drunk_strcmp(const char* s1, const char* s2)
{
	int i;

	i = 0;
	while (s1[i] == s2[i] && i < strlen(s1) && i < strlen(s2))
		i++;

	return (s1[i] - s2[i]);
}

unsigned char* drunk_memcpy(unsigned char* dest, const unsigned char* src, size_t len)
{
	size_t counter;

	counter = 0;
	if (src == NULL || dest == NULL)
		return (NULL);
	while (counter < len)
	{
		dest[counter] = src[counter];
		counter++;
	}
	return (dest);
}

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

const int drunk_atoi(const char* argv1)
{
	int i;
	int result;

	result = 0;
	for (i = 0; i < strlen(argv1); i++)
	{
		result = result * 10 + (argv1[i] - '0');
	}
	return (result);
}
