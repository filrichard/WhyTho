CXX			:= c++
CPPFLAGS	:= -Iinclude -MMD -MP
CXXFLAGS	:= -std=c++20 -Wall -Wextra -Wpedantic -Wconversion -O2
LDFLAGS		:=
LDLIBS		:=

UNAME_S 	:= $(shell uname -s)

BACKEND_SRC	:=
ifeq ($(UNAME_S),Darwin)
	CPPFLAGS += -DWHYTHO_MACOS
	BACKEND_SRC += src/backends/backend_macos.cpp
	LDLIBS +=
else ifeq ($(UNAME_S),Linux)
	CPPFLAGS += -DWHYTHO_LINUX
	BACKEND_SRC += src/backends/backend_linux.cpp
	LDLIBS +=
else
	$(error Unsupported OS: $(UNAME_S))
endif

BIN_DIR   := bin
BUILD_DIR := build

APP       := $(BIN_DIR)/whytho
TESTS     := $(BIN_DIR)/tests

SRC_COMMON := \
  src/main.cpp \
  src/procinfo.cpp \
  src/analyzer.cpp \
  src/render.cpp \
  src/backends/backend_common.cpp \
  src/utils/fs.cpp \
  src/utils/str.cpp \
  src/utils/hash.cpp \
  src/utils/time.cpp \
  $(BACKEND_SRC)

OBJ_COMMON := $(patsubst %.cpp,$(BUILD_DIR)/%.o,$(SRC_COMMON))
DEP_COMMON := $(OBJ_COMMON:.o=.d)

TEST_SRC := \
  tests/test_analyzer.cpp \
  src/analyzer.cpp \

OBJ_TEST := $(patsubst %.cpp,$(BUILD_DIR)/%.o,$(TEST_SRC))
DEP_TEST := $(OBJ_TEST:.o=.d)

.PHONY: all clean test run fmt

all: $(APP)

$(APP): $(OBJ_COMMON) | $(BIN_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@ $(LDLIBS)

$(TESTS): $(OBJ_TEST) | $(BIN_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@ $(LDLIBS)

$(BUILD_DIR)/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

test: $(TESTS)
	./$(TESTS)

run: $(APP)
	./$(APP) self

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)

-include $(DEP_COMMON)
-include $(DEP_TEST)