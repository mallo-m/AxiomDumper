UTILS_PATH = ./src/utils/
UTILS =	drunk_strdup.cpp		\
	drunk_atoi.cpp			\
	drunk_atoi_hex.cpp		\
	drunk_strrstr.cpp		\
	drunk_strcat.cpp		\
	drunk_strcpy.cpp		\
	drunk_cstring_to_wchar.cpp	\
	drunk_wchar_to_cstring.cpp	\
	drunk_random_string.cpp		\
	detect_edr.cpp			\
	get_address.cpp			\
	privcheck.cpp

UTILS_SRCS = $(addprefix $(UTILS_PATH),$(UTILS))
SRCS += $(UTILS_SRCS)

