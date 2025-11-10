#include "Glibc.h"

char* drunk_strrstr(const char* s, int c)
{
	int			i;
	const char* ini;

	ini = s;
	i = strlen(s);
	s = (s + i);
	while (s != ini && c != *s)
		s--;
	if (c == *s)
		return ((char*)s);
	return (0);
}

