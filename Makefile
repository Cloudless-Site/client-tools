# Makefile per Cloudless Client Tools
# Supporta cross-compilazione per x64, ARM, ARM64 e Windows

# --- Compilatori ---
# Assicurati di avere questi pacchetti installati (es. su Debian/Ubuntu):
# sudo apt install gcc-mingw-w64 gcc-arm-linux-gnueabihf gcc-aarch64-linux-gnu

CC_LINUX  = gcc
CC_WIN    = x86_64-w64-mingw32-gcc
CC_ARM    = arm-linux-gnueabihf-gcc
CC_ARM64  = aarch64-linux-gnu-gcc

# --- Flags ---
# Static build for portability (No PIE usually for full static)
SEC_FLAGS_TOOLS = -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fno-strict-aliasing -Wl,-z,relro -Wl,-z,now
CFLAGS    = -O2 -Wall -Wextra $(SEC_FLAGS_TOOLS)
LDFLAGS   = -static -pthread
LD_WIN    = -static -pthread -lws2_32

# --- Directories ---
SRC_DIR   = src
BIN_DIR   = bin

# --- Targets ---

.PHONY: all linux-x64 linux-arm linux-arm64 windows-x64 clean

all: linux-x64 linux-arm linux-arm64 windows-x64
	@echo "-----------------------------------------------------"
	@echo "Build completata! Controlla la cartella '$(BIN_DIR)/'"
	@echo "-----------------------------------------------------"

# 1. Linux x64 (Host standard)
linux-x64:
	@mkdir -p $(BIN_DIR)/linux-x64
	@echo "[Linux x64] Compiling..."
	$(CC_LINUX) $(CFLAGS) $(SRC_DIR)/kite.c -o $(BIN_DIR)/linux-x64/kite $(LDFLAGS)
	$(CC_LINUX) $(CFLAGS) $(SRC_DIR)/sendto.c -o $(BIN_DIR)/linux-x64/sendto $(LDFLAGS)
	$(CC_LINUX) $(CFLAGS) $(SRC_DIR)/recvfrom.c -o $(BIN_DIR)/linux-x64/recvfrom $(LDFLAGS)

# 2. Windows x64 (Cross-compile MinGW)
windows-x64:
	@mkdir -p $(BIN_DIR)/windows-x64
	@echo "[Windows x64] Compiling..."
	$(CC_WIN) $(CFLAGS) $(SRC_DIR)/kite.c -o $(BIN_DIR)/windows-x64/kite.exe $(LD_WIN)
	$(CC_WIN) $(CFLAGS) $(SRC_DIR)/sendto.c -o $(BIN_DIR)/windows-x64/sendto.exe $(LD_WIN)
	$(CC_WIN) $(CFLAGS) $(SRC_DIR)/recvfrom.c -o $(BIN_DIR)/windows-x64/recvfrom.exe $(LD_WIN)

# 3. Linux ARM (32-bit / Raspberry Pi Zero/2/3)
linux-arm:
	@mkdir -p $(BIN_DIR)/linux-arm
	@echo "[Linux ARMv7] Compiling..."
	$(CC_ARM) $(CFLAGS) $(SRC_DIR)/kite.c -o $(BIN_DIR)/linux-arm/kite $(LDFLAGS)
	$(CC_ARM) $(CFLAGS) $(SRC_DIR)/sendto.c -o $(BIN_DIR)/linux-arm/sendto $(LDFLAGS)
	$(CC_ARM) $(CFLAGS) $(SRC_DIR)/recvfrom.c -o $(BIN_DIR)/linux-arm/recvfrom $(LDFLAGS)

# 4. Linux ARM64 (64-bit / Raspberry Pi 4/5, OrangePi, VPS ARM)
linux-arm64:
	@mkdir -p $(BIN_DIR)/linux-arm64
	@echo "[Linux ARM64] Compiling..."
	$(CC_ARM64) $(CFLAGS) $(SRC_DIR)/kite.c -o $(BIN_DIR)/linux-arm64/kite $(LDFLAGS)
	$(CC_ARM64) $(CFLAGS) $(SRC_DIR)/sendto.c -o $(BIN_DIR)/linux-arm64/sendto $(LDFLAGS)
	$(CC_ARM64) $(CFLAGS) $(SRC_DIR)/recvfrom.c -o $(BIN_DIR)/linux-arm64/recvfrom $(LDFLAGS)

clean:
	@echo "Pulizia binari..."
	rm -rf $(BIN_DIR)/*
