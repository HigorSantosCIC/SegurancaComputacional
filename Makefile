EXEC_NAME := seguranca
BUILD_DIR := build
SRC_DIR := src
DEP_DIR := $(BUILD_DIR)/.deps
OBJ_DIR := $(BUILD_DIR)/.objs

# Make does not offer a recursive wildcard function, so here's one:
rwildcard=$(wildcard $1$2) $(foreach d,$(wildcard $1*),$(call rwildcard,$d/,$2))

SRCS := $(shell find src -name '*.cpp')
MAKE_DIR = @mkdir -p $(@D)
DEL_FILES = $(RM) *~ $(OBJS) $(DEPS) $(EXEC)
EXEC := $(EXEC_NAME).out

OBJS := $(SRCS:$(SRC_DIR)/%.cpp=$(OBJ_DIR)/%.o)
DEPS := $(SRCS:$(SRC_DIR)/%.cpp=$(DEP_DIR)/%.d)
DEPFLAGS = -MT $@ -MMD -MP -MF $(DEP_DIR)/$*.d
CXX := g++
INCLUDES := -I"include/" -I"lib"
CXXFLAGS := -std=c++17
CFLAGS := -g -Wall -pedantic -Wpedantic -Werror -lm -pthread
EXTERNAL_LINK_OBJS := sha3.o

.PHONY: all clean docs

all: $(EXEC)

$(EXEC): $(OBJS)
	@echo Generating executable $@
	@$(CXX) $^ $(CXXFLAGS) $(INCLUDES) $(CFLAGS) -o $@ $(EXTERNAL_LINK_OBJS)

$(DEP_DIR)/%.d: $(SRC_DIR)/%.cpp
	@$(MAKE_DIR)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp $(DEP_DIR)/%.d
	@$(MAKE_DIR)
	@echo Compiling $<
	@$(CXX) -c $< $(DEPFLAGS) $(CXXFLAGS) $(INCLUDES) $(CFLAGS) -o $@

$(DEPS):
include $(wildcard $(DEPS))

clean:
	@$(DEL_FILES)

fix:
	@clang-format -style=google -dump-config > .clang-format
	@echo Formatting src/ and include/
	@./formatter $(SRC_DIR) && ./formatter include/
	@rm ./.clang-format

docs:
	doxygen ./Doxyfile

-include $(wildcard $(DEPS))