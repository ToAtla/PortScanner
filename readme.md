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
The executable needs to be run as root to be able to create raw sockets.

On your machine run:
`$sudo ./scanner IP_ADDRESS PORT_NUMBER_START PORT_NUMBER_END`
and the scanner will ping each of the ports in the inclusive range with an ICMP packet.

If the scanner finds anything interesting, the results will be printed to the command line.

Quit the program preemptively with escape characters ( presumably CTRL+C ).
Otherwise the program ends after the scanning.

## Assumptions and measures

A UDP packet sent successfully to an open port will yield no result. However, a packet sent to a closed port will(or should) result in an ICMP Error being sent back.
We can therefore extrapolate which ports are open.
As UDP is an unreliable protocol we repeat each port "door-knock" three times, to give the ICMP error messages ample chance to arrive.

The formula for UDP usage is:

socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) //creating the raw socket for an ICMP echo message
sendto(...) // Ping the port on the ip
recvfrom(...) // Accept the answer/error message
close(...) // for good measure

## Resources and Inspiration

https://github.com/seifzadeh/c-network-programming-best-snipts/blob/master/Programming%20raw%20udp%20sockets%20in%20C%20on%20Linux

https://www.geeksforgeeks.org/udp-server-client-implementation-c/

https://www.mycplus.com/source-code/c-source-code/udp-sender-and-receiver/

http://www.ouah.org/portscandethly.pdf

https://opensourceforu.com/2015/03/a-guide-to-using-raw-sockets/

https://packages.debian.org/stable/net/iputils-ping

https://www.geeksforgeeks.org/ping-in-c/
