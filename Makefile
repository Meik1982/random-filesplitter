CXX ?= g++
CXXFLAGS ?= -O3 -Wall -Wextra -std=c++11 -pthread -Iinclude
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

# Automatische AVX2-Erkennung, falls die CPU es unterstützt
ARCH_FLAGS ?= -mavx2

SRCS = src/chacha20.cpp src/sha256.cpp src/entropy.cpp src/splitter.cpp
OBJS = $(SRCS:.cpp=.o)

TARGET = rfs
TEST_TARGET = test_crypto

.PHONY: all test benchmark entropy clean install uninstall

all: $(TARGET)

$(TARGET): $(OBJS) src/main.o
	$(CXX) $(CXXFLAGS) $(ARCH_FLAGS) $^ -o $@

src/%.o: src/%.cpp
	$(CXX) $(CXXFLAGS) $(ARCH_FLAGS) -c $< -o $@

tests/%.o: tests/%.cpp
	$(CXX) $(CXXFLAGS) $(ARCH_FLAGS) -c $< -o $@

$(TEST_TARGET): $(OBJS) tests/test_crypto.o
	$(CXX) $(CXXFLAGS) $(ARCH_FLAGS) $^ -o $@

test: $(TEST_TARGET)
	./$(TEST_TARGET)

benchmark: $(TARGET)
	./$(TARGET) --benchmark

entropy: $(TARGET)
	./$(TARGET) --entropy-test

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)

clean:
	rm -f src/*.o tests/*.o $(TARGET) $(TEST_TARGET)
