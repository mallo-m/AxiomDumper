#ifndef GLIBC_H
# define GLIBC_H

# include <windows.h>
# include <stdlib.h>
# include <string.h>
# include <stdint.h>

# ifndef SEED
#  define SEED 0x56137378 // Idea: do like a constexpr fnv1a_32(__TIMESTAMP__) to automatically generate a new seed at each compilation ?

#  define A (SEED ^ (__COUNTER__ * 42424242))
#  define B (SEED ^ (__COUNTER__ * 80000085))
#  define C (SEED ^ (__COUNTER__ * 69420001))
#  define D (SEED ^ (__COUNTER__ * 13371337))
# endif

# define F(X, Y, Z) ((X & Y) | (~X & Z))
# define G(X, Y, Z) ((X & Z) | (Y & ~Z))
# define H(X, Y, Z) (X ^ Y ^ Z)
# define I(X, Y, Z) (Y ^ (X | ~Z))

char* drunk_random_string(SIZE_T len);
char* drunk_md5(const char* input);
const char* drunk_strdup(const char* str);
const int drunk_strcmp(const char* s1, const char* s2);
unsigned char* drunk_memcpy(unsigned char* dest, const unsigned char* src, size_t len);
const int drunk_atoi(const char* argv1);
uint64_t drunk_atoi_hex(const char* str);
const char* drunk_wchar_to_cstring(wchar_t* source);
LPWSTR drunk_cstring_to_wchar(char* str);
const char* drunk_strcpy(char* dest, const char* src);
const char* drunk_strcat(char* dest, const char* src);
char* drunk_strrstr(const char* s, int c);

//=============================================================================
//|                                  MD5-Shit                                 |
//=============================================================================
typedef struct {
    uint64_t size;        // Size of input in bytes
    uint32_t buffer[4];   // Current accumulation of hash
    uint8_t input[64];    // Input to be used in the next step
    uint8_t digest[16];   // Result of algorithm
}mutate5Context;

#endif
