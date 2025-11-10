CORE_PATH = ./src/core/
CORE =	main.cpp	\
	parse_args.cpp

CORE_SRCS = $(addprefix $(CORE_PATH),$(CORE))
SRCS += $(CORE_SRCS)

