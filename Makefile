CC = gcc
CFLAGS = -shared -fPIC
TARGET = inject_server.so
SOURCE = inject_server.c
PYTHON_VERSION = python3.12
INCLUDE_DIRS = -I/usr/include/$(PYTHON_VERSION)/
LIB_DIRS = -L/usr/lib/
LIBS = -l$(PYTHON_VERSION) -ldl -lm

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE) $(INCLUDE_DIRS) $(LIB_DIRS) $(LIBS)

clean:
	rm -f $(TARGET)
