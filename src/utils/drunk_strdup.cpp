#include "Glibc.h"

const char* drunk_strdup(const char* str)
{
	char* res;
	char* cursor;

	if (str == NULL)
		return (NULL);
	cursor = res = (char*)malloc(sizeof(char) + strlen(str) + 1);
	if (cursor == NULL)
		return (NULL);
	while (*str != '\0')
		*cursor++ = *str++;
	*cursor = '\0';
	return (res);
}

