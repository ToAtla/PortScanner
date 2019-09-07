all: clean scanner

scanner:
	g++ -Wall -std=c++11 scanner.cpp -o scanner
clean:
	rm -f scanner
