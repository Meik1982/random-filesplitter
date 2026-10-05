CXX ?= g++
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

# Härtungs- & Sicherheits-Flags (Full-RELRO, Stack-Clash, Fortify Source 3, PIE)
HARDENING_CXXFLAGS = -fstack-protector-strong -fstack-clash-protection -D_FORTIFY_SOURCE=3 -fPIE
HARDENING_LDFLAGS = -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack

CXXFLAGS ?= -O3 -Wall -Wextra -std=c++17 -pthread -Iinclude $(HARDENING_CXXFLAGS) -MMD -MP
LDFLAGS ?= -pthread $(HARDENING_LDFLAGS)

# Automatische AVX2-Erkennung, falls die CPU es unterstützt
ARCH_FLAGS ?= -mavx2

SRCS = src/chacha20.cpp src/sha256.cpp src/entropy.cpp src/splitter.cpp
OBJS = $(SRCS:.cpp=.o)
DEPS = $(OBJS:.o=.d) src/main.d tests/test_crypto.d

TARGET = rfs
TEST_TARGET = test_crypto

.PHONY: all release asan ubsan test benchmark entropy clean install uninstall

all: $(TARGET)

release: clean
	$(MAKE) CXXFLAGS="-O3 -DNDEBUG -flto -Wall -Wextra -std=c++17 -pthread -Iinclude $(HARDENING_CXXFLAGS) -MMD -MP" \
	        LDFLAGS="-flto -Wl,-O1,--sort-common,--as-needed $(HARDENING_LDFLAGS)" \
	        all
	strip --strip-all $(TARGET)
	@echo "=== Release-Build erfolgreich (Full-RELRO, -O3, LTO, gestrippt) ==="

asan: clean
	$(MAKE) CXXFLAGS="-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -Wall -Wextra -std=c++17 -pthread -Iinclude -MMD -MP" \
	        LDFLAGS="-fsanitize=address,undefined -pthread $(HARDENING_LDFLAGS)" \
	        test
	@echo "=== AddressSanitizer & UndefinedBehaviorSanitizer: Alle Tests bestanden! ==="

ubsan: clean
	$(MAKE) CXXFLAGS="-O1 -g -fsanitize=undefined -fno-omit-frame-pointer -Wall -Wextra -std=c++17 -pthread -Iinclude -MMD -MP" \
	        LDFLAGS="-fsanitize=undefined -pthread $(HARDENING_LDFLAGS)" \
	        test
	@echo "=== UndefinedBehaviorSanitizer: Alle Tests bestanden! ==="

$(TARGET): $(OBJS) src/main.o
	$(CXX) $(CXXFLAGS) $(ARCH_FLAGS) $^ -o $@ $(LDFLAGS)

src/%.o: src/%.cpp
	$(CXX) $(CXXFLAGS) $(ARCH_FLAGS) -c $< -o $@

tests/%.o: tests/%.cpp
	$(CXX) $(CXXFLAGS) $(ARCH_FLAGS) -c $< -o $@

$(TEST_TARGET): $(OBJS) tests/test_crypto.o
	$(CXX) $(CXXFLAGS) $(ARCH_FLAGS) $^ -o $@ $(LDFLAGS)

-include $(DEPS)

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
	rm -f src/*.o src/*.d tests/*.o tests/*.d $(TARGET) $(TEST_TARGET)
