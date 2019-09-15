# Project 1 - Readme

Welcome to the readme file for our project.
- **Student:** Þórður Atlason, **E-mail** thorduratl17@ru.is
- **Student:** Þórður Friðriksson, **E-mail** thordurf17@ru.is



## Compilation

Run the **makefile** with the command:
`$make`
That should run the following commands:
`$rm -f scanner`
and
`$g++ -std=c++11 scanner.cpp -o scanner`
This makefile has been tested on MacOS and compiels the scanner.

This makefile has been tesdted on linux and compiels the scanner.

## Usage

### Scanner
The executable needs to be run as root to be able to create raw sockets.

On your machine run:
`$sudo ./scanner IP_ADDRESS PORT_NUMBER_START PORT_NUMBER_END`
and the scanner will send a udp packet to each port in the range specified.

If the scanner finds anything interesting (gets back a udp message), the results will be printed to the command line.
As well as any neccesary data extracted from the message.

The scanner has a timout for each receive of 0.5 seconds, this makes it rather slow but safe, if you wish to lower the timout and make it faster but unsafer be my guest.

Quit the program preemptively with escape characters ( presumably CTRL+C ).
Otherwise the program ends after the scanning.

### puzzles
From three of the open ports there were puzzles 

 - The first being that we only had to extract a given port from the message received in a.), we called this the ez port.
 - The second was that we needed to set the evil bit in our header and send it to the evil port to get another port.
 - The third was that we needed to send a specific correctly calculated checksum to the checksum port and get back a secret message.


### Oracle and knocking
Then we send the 4th open port, the oracle, the right sequence of ports and get the right order and number of knocks to use to knock on the hidden ports in the correct order and print out their messages.

Our program has a variable called VERBOSE, if you wish to not get a detailed step by step of whats happening turn it to 0.


## Assumptions and measures
As our code stands now the function "checskumPuzzle" returns a hardcoded return value because we did this assignment not on campus and therefore never got the secret message, it should work to replace the hard coded string with the response variable if on campus.

As UDP is unreliable we run the port scanner in a loop until we get 4 open ports.

As UDP is an unreliable protocol we repeat each port "door-knock" three times, to give the ICMP error messages ample chance to arrive.

The formula for UDP usage is:

 - socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) //creating the raw socket for an ICMP echo message
- sendto(...) // Ping the port on the ip
- recvfrom(...) // Accept the answer/error message
- close(...) // for good measure

## Resources and Inspiration

https://github.com/seifzadeh/c-network-programming-best-snipts/blob/master/Programming%20raw%20udp%20sockets%20in%20C%20on%20Linux

https://www.geeksforgeeks.org/udp-server-client-implementation-c/

https://www.mycplus.com/source-code/c-source-code/udp-sender-and-receiver/

http://www.ouah.org/portscandethly.pdf

https://opensourceforu.com/2015/03/a-guide-to-using-raw-sockets/

https://packages.debian.org/stable/net/iputils-ping

https://www.geeksforgeeks.org/ping-in-c/

https://tuprints.ulb.tu-darmstadt.de/6243/1/TR-18.pdf

https://www.binarytides.com/raw-udp-sockets-c-linux/
