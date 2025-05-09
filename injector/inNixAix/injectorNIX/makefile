CC = g++
CFLAGS = -O2 -Wall -g
DEBUG_FLAGS = -g -O0

TARGET = injectorNIX

SRCS = injectorNIX.cpp

OBJS = $(SRCS:.cpp=.o)

INCLUDE_PATH = 
LIB_PATH = 

LDFLAGS = -ldl -lpthread $(LIB_PATH)

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
