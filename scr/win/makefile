CXX = g++
CXXFLAGS = -Wall -std=c++11 -O2 -fPIC
LDFLAGS = -shared
INCLUDE_PATHS = -I"C:/path/to/openssl/include" -I"C:/path/to/detours/include" -I"C:/path/to/iso8583/include"
LIBRARY_PATHS = -L"C:/path/to/openssl/lib" -L"C:/path/to/detours/lib"
LIBS = -lws2_32 -lssl -lcrypto -ldetours
SRCS = renaski1.0.cpp iso8583.cpp
OBJS = $(SRCS:.cpp=.o)
TARGET = renaski.dll

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(LDFLAGS) -o $(TARGET) $(OBJS) $(LIBRARY_PATHS) $(LIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDE_PATHS) -c $< -o $@

clean:
	rm -f *.o $(TARGET)

.PHONY: all clean


