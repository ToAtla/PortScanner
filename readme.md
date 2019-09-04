# Project 1 - Readme

Welcome to the readme file for our project.
**Student:** Þórður Atlason
**E-mail** thorduratl17@ru.is
**Student:** Þórður Friðriksson
**E-mail** thordurf17@ru.is



## Compilation

Run the **makefile** with the command:
`$make`
That should run the following commands:
`$rm -f scanner`
and
`$g++ -std=c++11 scanner.cpp -o scanner`
This makefile has been tested on MacOS and complies the scanner.

## Usage

### Scanner
On your machine run:
`$./scanner IP_ADDRESS PORT_NUMBER_START PORT_NUMBER_END`
and the scanner will ping each of the ports in the inclusive range with an ICMP packet.

If the scanner finds anything interesting, the results will be printed to the command line.

Quit the program preemptively with escape characters ( presumably CTRL+C ).
Otherwise the program ends after the scanning.
