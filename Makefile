CC=gcc
CFLAGS=-Wall -Wextra -g
LIBS=-lpcap
BUILD_DIR=build
TARGET=$(BUILD_DIR)/vrrp

all: $(TARGET)
	chmod 755 $(TARGET)

$(TARGET): $(BUILD_DIR)/main.o $(BUILD_DIR)/vrrp.o $(BUILD_DIR)/vrrptimers.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

$(BUILD_DIR)/main.o: main.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/vrrp.o: vrrp.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/vrrptimers.o: vrrptimers.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -f $(BUILD_DIR)/*.o $(TARGET)
	rmdir $(BUILD_DIR)