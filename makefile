all: clean scanner

scanner:
	g++ -Wall -std=c++11 scanner.cpp -o scanner
clean:
	rm -f scanner
doddi:
	g++ -Wall -std=c++11 scanner_doddi.cpp -o scanner_doddi
