#include "Glibc.h"

const int drunk_atoi(const char* argv1)
{
	size_t i;
	int result;

	result = 0;
	for (i = 0; i < strlen(argv1); i++)
	{
		result = result * 10 + (argv1[i] - '0');
	}
	return (result);
}

