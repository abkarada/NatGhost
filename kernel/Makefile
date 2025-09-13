CXX = g++
CXXFLAGS = -std=c++17 -O3 -Wall -Wextra -pthread
TARGET = advanced_nat_analyzer
SOURCE = advanced_nat_analyzer.cpp

$(TARGET): $(SOURCE)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SOURCE)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	sudo setcap cap_net_raw+ep $(TARGET)

.PHONY: clean install
