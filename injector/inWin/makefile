CC = g++
CFLAGS = -O2 -Wall -std=c++17
DEBUG_FLAGS = -g -O0

TARGET = injectorW.exe

SRCS = injectorW.cpp

OBJS = $(SRCS:.cpp=.o)

INCLUDE_PATH = 
LIB_PATH = 

LDFLAGS = 

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

debug: CFLAGS += $(DEBUG_FLAGS)
debug: clean $(TARGET)

%.o: %.cpp
	$(CC) $(CFLAGS) $(INCLUDE_PATH) -c $< -o $@

clean:
	rm -f *.o $(TARGET)

.PHONY: all debug clean

