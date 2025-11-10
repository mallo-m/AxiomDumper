DM_PATH = ./src/driver_magic/
DM =	ntoskrnl_base.cpp		\
	get_ntoskrnl_version.cpp	\
	priv_increase.cpp		\
	drop_driver_to_disk.cpp		\
	add_driver_via_registry.cpp	\
	load_driver.cpp			\
	unload_driver.cpp		\
	shred_driver.cpp		\
	load_framework.cpp		\
	driver_primitives.cpp		\
	get_kernel_export.cpp		\
	spawn_handle.cpp		\
	read_virtual_memory.cpp		\
	get_process_peb.cpp		\
	query_virtual_memory.cpp

DM_SRCS = $(addprefix $(DM_PATH),$(DM))
SRCS += $(DM_SRCS)

