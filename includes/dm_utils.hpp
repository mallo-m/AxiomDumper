#ifndef DM_UTILS_H
# define DM_UTILS_H

# include <windows.h>
# include <ntstatus.h>
# include <cstdint>
# include <string_view>
# include <algorithm>
# include <map>
# include <stdio.h>

#include "AxiomDumper.h"
#include "Typedefs.h"

namespace util
{
	inline std::map<std::uintptr_t, std::size_t> pmem_ranges{};

#pragma pack (push, 1)
	struct PhysicalMemoryPage
	{
		uint8_t type;
		uint8_t shareDisposition;
		uint16_t flags;
		uint64_t pBegin;
		uint32_t sizeButNotExactly;
		uint32_t pad;

		static constexpr uint16_t cm_resource_memory_large_40{ 0x200 };
		static constexpr uint16_t cm_resource_memory_large_48{ 0x400 };
		static constexpr uint16_t cm_resource_memory_large_64{ 0x800 };

		uint64_t size()const noexcept
		{
			if (flags & cm_resource_memory_large_40)
				return uint64_t{ sizeButNotExactly } << 8;
			else if (flags & cm_resource_memory_large_48)
				return uint64_t{ sizeButNotExactly } << 16;
			else if (flags & cm_resource_memory_large_64)
				return uint64_t{ sizeButNotExactly } << 32;
			else
				return uint64_t{ sizeButNotExactly };
		}
	};
	static_assert(sizeof(PhysicalMemoryPage) == 20);
#pragma pack (pop)

	inline const auto init_ranges = ([]() -> bool
		{
			HKEY h_key;
			DWORD type, size;
			LPBYTE data;
			RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory", 0, KEY_READ, &h_key);
			RegQueryValueExA(h_key, ".Translated", NULL, &type, NULL, &size); //get size
			data = new BYTE[size];
			RegQueryValueExA(h_key, ".Translated", NULL, &type, data, &size);
			DWORD count = *(DWORD*)(data + 16);
			auto pmi = data + 24;
			for (DWORD dwIndex = 0; dwIndex < count; dwIndex++)
			{
#if 0
				pmem_ranges.emplace(*(uint64_t*)(pmi + 0), *(uint64_t*)(pmi + 8));
#else
				const PhysicalMemoryPage& page{ *(PhysicalMemoryPage*)(pmi - 4) };
				if (page.pBegin < 0x10000) {
					printf("[+] Ignoring page range at 0x%llx (%d)\n", page.pBegin, page.type);
				}
				else {
					printf("[+] Page at 0x%llx (%d)\n", page.pBegin, page.type);
					pmem_ranges.emplace(page.pBegin, page.size());
				}
#endif
				pmi += 20;
			}
			delete[] data;
			RegCloseKey(h_key);
			//exit(1);
			return (TRUE);
		})();
}

#endif

