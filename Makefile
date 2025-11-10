include mk/core.mk
include mk/elsass.mk
include mk/dm.mk
include mk/utils.mk

CC = gcc
CXX = x86_64-w64-mingw32-g++-win32
LIBS = -lws2_32 -lversion -lole32
LIBSFOLDERS = -L/usr/lib/x86_64-linux-gnu/
vpath %.cpp $(dir MAKEFILE_LIST)
CFLAGS = -Wall -Wextra -Werror -Wno-unused-result -Wno-unused-parameter -Wno-unused-function -Wno-ignored-qualifiers -Wno-narrowing -I./includes
CPPFLAGS += -MMD -MP
OBJDIR = .o
UNAME = $(shell uname)
NAME = AxiomDumper
UNXOR = unxor

OBJS = $(subst .cpp,.o,$(subst ./src/,./$(OBJDIR)/,$(SRCS)))
DEPS = $(subst .cpp,.d,$(subst ./src/,./$(OBJDIR)/,$(SRCS)))

all: $(NAME) $(UNXOR)

$(UNXOR): src/unxor/unxor.c
	@$(CC) src/unxor/unxor.c -o unxor

$(NAME): $(OBJS)
	@$(RM) tmp_log
	@$(RM) tmp_errors
	@if [ -e files_missing ]; then \
		printf "\033[1;31m\n[COMPILATION FAILED]\033[0m\n"; \
	else \
		$(CXX) -s -static $(OBJS) -o $(NAME) $(LIBSFOLDERS) $(LIBS) && \
			printf "\033[1;36m\n[COMPILATION SUCCESSFUL]\033[0m\n" || \
			printf "\033[1;31m\n[COMPILATION FAILED]\033[0m\n"; \
		chown 1000:users $(NAME).exe >/dev/null 2>&1; \
	fi;
	@$(RM) files_missing
	@$(RM) /tmp/.makefile_link

$(OBJDIR):
	@$(shell mkdir -p $(OBJDIR))

$(OBJDIR)/%.o: src/%.cpp | $(OBJDIR)
	@$(shell mkdir -p $(dir $@))
	@$(shell touch /tmp/.makefile_link)
	@printf "%-50s" "Precompiling $(notdir $@)..."
	@$(CXX) $(CFLAGS) $(CPPFLAGS) -c -o $@ $< 2> ./tmp_log || touch ./tmp_errors
	@if [ -e tmp_errors ]; then \
		printf "\033[1;31m[KO]\n\033[0m" && cat 1>&2 ./tmp_log && touch files_missing; \
	elif test -s ./tmp_log; then \
		printf "\033[1;33m[WARNING]\n\033[0m" && cat ./tmp_log; \
	else \
		printf "\033[1;32m[OK]\n\033[0m"; \
	fi;
	@$(RM) ./tmp_errors

clean:
	@$(RM) $(OBJS) $(DEPS)
	@printf "\033[1;33m[OBJECT FILES CLEANED]\033[0m\n"

fclean:
	@$(RM) $(OBJS) $(DEPS)
	@printf "\033[1;33m[OBJECT FILES CLEANED]\033[0m\n"
	@$(RM) $(NAME)
	@printf "\033[1;35m[BINARY DELETED]\033[0m\n"

re: fclean all

.PHONY: all clean fclean re re_nolib fclean_nolib
-include $(DEPS)

