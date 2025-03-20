# Compiler and flags
CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++17 -O2 -Iinclude
LDFLAGS = -L. -lknet -lcrypto

# Directories
SRC_DIR = src
BUILD_DIR = build
EXAMPLES_DIR = examples
INCLUDE_DIR = include

# Library and executables
LIBKNET = libknet.a
SEND_PACKET = send_packet
RECEIVE_PACKET = receive_packet

# Source and object files
SRC_FILES = $(SRC_DIR)/knet.cpp
OBJ_FILES = $(BUILD_DIR)/knet.o

# Example programs
SEND_SRC = $(EXAMPLES_DIR)/send_packet.cpp
RECEIVE_SRC = $(EXAMPLES_DIR)/receive_packet.cpp

# Default target
all: $(LIBKNET) $(SEND_PACKET) $(RECEIVE_PACKET)

# Compile KNet library
$(LIBKNET): $(OBJ_FILES)
	ar rcs $@ $^

# Compile KNet object files
$(BUILD_DIR)/knet.o: $(SRC_FILES) $(INCLUDE_DIR)/knet.h
	mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Compile example programs
$(SEND_PACKET): $(SEND_SRC) $(LIBKNET)
	$(CXX) $(CXXFLAGS) $< -o $@ -L. -lknet -lcrypto

$(RECEIVE_PACKET): $(RECEIVE_SRC) $(LIBKNET)
	$(CXX) $(CXXFLAGS) $< -o $@ -L. -lknet -lcrypto

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR) $(LIBKNET) $(SEND_PACKET) $(RECEIVE_PACKET)

