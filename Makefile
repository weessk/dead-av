CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -static-libgcc -static-libstdc++
LDFLAGS = -static -ladvapi32 -lkernel32 -luser32 -lpsapi
TARGET = avk
SRCDIR = src
SOURCES = $(wildcard $(SRCDIR)/*.cpp)
OBJECTS = $(SOURCES:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(OBJECTS) -o $(TARGET) $(LDFLAGS)
	@echo "Build complete: $(TARGET).exe"

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET).exe
	@echo "Clean complete"

release: CXXFLAGS += -DNDEBUG -s
release: clean $(TARGET)
	@echo "Release build complete"

debug: CXXFLAGS += -DDEBUG -g
debug: clean $(TARGET)
	@echo "Debug build complete"

.PHONY: all clean release debug