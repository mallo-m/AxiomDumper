ELSASS_PATH = ./src/elsass/
ELSASS =	elsass.cpp	\
		helpers.cpp	\
		modules.cpp	\
		pages.cpp	\
		find_pid.cpp

ELSASS_SRCS = $(addprefix $(ELSASS_PATH),$(ELSASS))
SRCS += $(ELSASS_SRCS)

