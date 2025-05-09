CC = g++
CFLAGS = -O2 -fPIC
LDFLAGS = -shared
TARGET = renaski.so
LIBS = -lssl -lcrypto -lpthread -ldl
SRCS = renaski1.1.cpp iso8583.cpp
OBJS = $(SRCS:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET) $(LDFLAGS) $(LIBS)

%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJS)

install: $(TARGET)
	cp $(TARGET) /usr/local/lib
	cp iso8583.h /usr/local/include

.PHONY: all clean install
