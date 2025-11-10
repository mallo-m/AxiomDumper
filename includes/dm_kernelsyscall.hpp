#ifndef DM_CTX_H
# define DM_CTX_H

# include <windows.h>
# include <string_view>
# include <vector>
# include <thread>
# include <atomic>
# include <mutex>
# include <functional>

# include "dm.h"
# include "dm_utils.hpp"

template <class T, class ... Ts>
__forceinline std::invoke_result_t<T, Ts...> DM_KernelSyscall(void* addr, Ts ... args)
{
	static const auto proc = GetProcAddress(LoadLibraryA(SYSCALL_DLL), SYSCALL_HOOK);

	// jmp [rip+0x0]
	std::uint8_t jmp_code[] =
	{
		0xff, 0x25, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00
	};

	std::uint8_t orig_bytes[sizeof jmp_code];
	*reinterpret_cast<void**>(jmp_code + 6) = addr;
	g_read_phys(g_syscall_address, orig_bytes, sizeof orig_bytes);

	// execute hook...
	g_write_phys(g_syscall_address, jmp_code, sizeof jmp_code);
	auto result = reinterpret_cast<T>((void*)proc)(args ...);
	g_write_phys(g_syscall_address, orig_bytes, sizeof orig_bytes);

	return result;
}

#endif

