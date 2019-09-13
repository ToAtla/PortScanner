all: clean doddi

scanner:
	g++ -Wall -std=c++11 scanner.cpp -o scanner
clean:
	rm -f scanner && rm -f scanner_doddi
doddi:
	g++ -Wall -std=c++11 scanner_doddi.cpp -o scanner_doddi
