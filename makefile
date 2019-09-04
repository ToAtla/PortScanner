all: clean scanner

scanner:
	g++ -std=c++11 scanner.cpp -o scanner
clean:
	rm -f scanner
