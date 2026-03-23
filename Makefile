CC = gcc
CFLAGS = -Wall -Wextra -O3
LDFLAGS = -lgmp

BUILD_DIR = build

LIB_SRC = code/lib/chacha20.c code/lib/poly1305.c code/lib/aead.c
MAIN_SRC = code/main.c
AEAD_WRAP_SRC = code/aead_wrap.c
AEAD_UNWRAP_SRC = code/aead_unwrap.c

LIB_OBJ = $(BUILD_DIR)/chacha20.o $(BUILD_DIR)/poly1305.o $(BUILD_DIR)/aead.o
MAIN_OBJ = $(BUILD_DIR)/main.o
AEAD_WRAP_OBJ = $(BUILD_DIR)/aead_wrap.o
AEAD_UNWRAP_OBJ = $(BUILD_DIR)/aead_unwrap.o

TARGET_APP = chacha20
TARGET_AEAD_WRAP = aead_wrap
TARGET_AEAD_UNWRAP = aead_unwrap

all: $(TARGET_APP) $(TARGET_AEAD_WRAP) $(TARGET_AEAD_UNWRAP)

$(TARGET_APP): $(LIB_OBJ) $(MAIN_OBJ)
	@echo "Linking chacha20..."
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)
	@echo "Built $(TARGET_APP)."

$(TARGET_AEAD_WRAP): $(LIB_OBJ) $(AEAD_WRAP_OBJ)
	@echo "Linking aead_wrap..."
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)
	@echo "Built $(TARGET_AEAD_WRAP)."

$(TARGET_AEAD_UNWRAP): $(LIB_OBJ) $(AEAD_UNWRAP_OBJ)
	@echo "Linking aead_unwrap..."
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)
	@echo "Built $(TARGET_AEAD_UNWRAP)."

$(BUILD_DIR)/chacha20.o: code/lib/chacha20.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/poly1305.o: code/lib/poly1305.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/aead.o: code/lib/aead.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/main.o: $(MAIN_SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/aead_wrap.o: $(AEAD_WRAP_SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/aead_unwrap.o: $(AEAD_UNWRAP_SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR):
	mkdir -p $@

clean:
	rm -rf $(BUILD_DIR) $(TARGET_APP) $(TARGET_AEAD_WRAP) $(TARGET_AEAD_UNWRAP) ciphertext.bin my_ciphertext.bin my_sunscreen.txt
	@echo "Cleaned up."

.PHONY: all clean
