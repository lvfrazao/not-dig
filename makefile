CC = gcc
CFLAGS = -O3 -Wall
TARGET = not-dig
TARGET_PATH = ./src/stub_resolver/

TEST_TARGET = dns-test
TEST_PATH = ./test/test_dns_packet.c

all: $(TARGET)

$(TARGET): $(TARGET_PATH)$(TARGET).c
	$(MAKE) $(TEST_TARGET)
	$(CC) $(CFLAGS) $(TARGET_PATH)$(TARGET).c -o $(BUILD_PATH)$(TARGET)

clean:
	$(RM) $(TARGET)
	$(RM) $(TEST_TARGET)

test: $(TEST_TARGET)

$(TEST_TARGET): $(TEST_PATH)
	$(CC) $(CFLAGS) -o $(TEST_TARGET) $(TEST_PATH)
	./dns-test
