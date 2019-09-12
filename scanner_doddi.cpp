#include <iostream>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>
#include "ipx.h"

#ifdef __APPLE__
		#include <netinet/ip.h>
		#include <netinet/udp.h>
#else
		#include <linux/ip.h>
		#include <linux/udp.h>
#endif

using namespace std;

int high_port;
int low_port;
char *ip_address;
struct sockaddr_in server_socket_addr; // address of server
const int OPENPORTCOUNT = 4;
int openPorts[OPENPORTCOUNT];
int hiddenPorts[2];
int portGivenByEz;
int checksumGivenByPort;

// indexes of the open ports
const int EVILPORT = 0;
const int EZPORT = 1;
const int CHECKSUMPORT = 2;
const int ORACLEPORT = 3;

// open port keywords
const string EVILKEY = "evil";
const string EZKEY = "port:";
const string CHECKSUMKEY = "checksum";
const string ORACLEKEY = "oracle";

// gets the index for a specific port for the openPorts array
int getOpenPortIndex(string message)
{
	int portIndex = -1;
	if (message.find(EVILKEY) != string::npos)
		portIndex = EVILPORT;

	else if (message.find(EZKEY) != string::npos)
		portIndex = EZPORT;

	else if (message.find(CHECKSUMKEY) != string::npos)
		portIndex = CHECKSUMPORT;

	else if (message.find(ORACLEKEY) != string::npos)
		portIndex = ORACLEPORT;

	return portIndex;
}

/*
scans UDP ports for a given address and a given port range.
prints out open port messages and details
sets open ports vector
*/
int findOpenPorts()
{
	// TODO: if a udp thing drops the packet of an open port, what to do?
	// iterate through each portnumber in the range given
	for (int portno = low_port; portno <= high_port; portno++)
	{
		// TODO: why does this have to  be inside the for loop?
		// socket to send to udp ports with IPv4 protocol
		int socketFd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (socketFd < 0)
		{
			perror("Failed to open send socket");
			return (-1);
		}

		// need this datastructure for select() to utilize the timeout
		fd_set sockets;
		FD_SET(socketFd, &sockets);

		server_socket_addr.sin_port = htons(portno); // portnumber
		socklen_t socklen = sizeof(server_socket_addr);

		// send string to server
		string sendString = "knock";
		sendto(socketFd, sendString.c_str(), sendString.size() + 1, 0, (sockaddr *)&server_socket_addr, socklen);

		// initalize the response buffer
		int responseSize = 6000;
		char response[responseSize];
		memset(response, 0, responseSize); // zero initialize char array

		// select socketFd if there is some data to be read within the timout
		// TODO: whats a good timeout?
		struct timeval timeout;
		timeout.tv_sec = 0;
		timeout.tv_usec = 500000; // half a second
		if (select(socketFd + 1, &sockets, NULL, NULL, &timeout) > 0)
		{
			int byteCount = recvfrom(socketFd, response, responseSize, 0, (sockaddr *)&server_socket_addr, &socklen);
			if (byteCount < 0)
			{
				cout << "error receiving output from server" << endl;
			}
			else
			{
				response[byteCount] = '\0'; // make sure to end the string at the right spot so we dont read of out memory
				cout << "-----------------------" << endl;
				cout << response << endl;
				cout << "Byte count received: " << byteCount << ", "
					 << "on port: " << portno << endl;
				cout << "-----------------------" << endl;

				// put the open port in its rightful place in the array.
				string responseString(response);
				int portIndex = getOpenPortIndex(responseString);
				if (portIndex < 0)
				{
					perror("could not determine open port");
					return (-1);
				}
				openPorts[portIndex] = portno;

				// extract the port that is given by the "ez port"
				if (portIndex == EZPORT)
				{
					int beginIndex = responseString.find(":") + 1;
					portGivenByEz = atoi(responseString.substr(beginIndex).c_str());
				}
				// extract the checksum that is given by the "checksum port"
				else if (portIndex == CHECKSUMPORT)
				{
					int beginIndex = responseString.find("value of") + 9;
					checksumGivenByPort = atoi(responseString.substr(beginIndex).c_str());
				}
			}
		}
		close(socketFd);
	}

	return 1;
}

void printOpenPorts()
{
	for (int i = 0; i < OPENPORTCOUNT; i++)
	{
		cout << openPorts[i] << endl;
	}
}

string getMyIp()
{
	return "10.0.2.15";
}

void populateIPx(struct IPx *ipx, char* myIp, int packetLength)
{
	// TODO: why 5?
	ipx->ihl = 5;				   // header length
	ipx->version = 4;			   // ipv4
	ipx->tot_len = packetLength; // total length of packet
	ipx->id = 12345;			   // just some identification
	ipx->ttl = 0xFF;			   // time to live as much as possible
	ipx->protocol = IPPROTO_UDP; // set to udp protocol
	ipx->saddr = inet_addr(myIp);
	ipx->daddr = inet_addr(ip_address);
}

void populateudpHdrx(struct udphdrx *udpHdrx, int myPortNo, int destPortNo, int messageSize)
{
	udpHdrx->source = myPortNo;
	udpHdrx->dest = destPortNo;
	udpHdrx->len = sizeof(udpHdrx) + messageSize; // length of udp header + udp data
	udpHdrx->check = 0;
	cout << "udp length: " << sizeof(udpHdrx) + messageSize << endl;
}

/*
solve the three puzzle ports to get the 2 hidden ports
1. "This is the port:xxxx"
2. "I only speak with fellow evil villains. (https://en.wikipedia.org/wiki/Evil_bit)"
3. "Please send me a message with a valid udp checksum with value of xxxxx"
*/
int answerMeTheseRiddlesThree()
{
	// first lets do the checksum puzzle
	struct IPx *ipx;
	struct udphdrx *udpHdrx;
	char *data;
	char message[] = "knock\0";
	int packetLength = sizeof(struct IPx) + sizeof(struct udphdrx) + sizeof(message);

	// TODO: how big should this be?
	char packet[packetLength];
	memset(packet, 0, sizeof(packet));

	// make pointers point to where they should point on the packet
	ipx = (IPx *) packet;
	udpHdrx = (udphdrx *)(packet + sizeof(ipx));
	data = (char *)(packet + sizeof(ipx) + sizeof(udpHdrx));

	// write the message into its appropriate place within the packet
	strcpy(data, message);

	// set destination port
	server_socket_addr.sin_port = htons(openPorts[CHECKSUMPORT]);

	// raw socket without andy protocol header
	int socketFd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (socketFd < 0)
	{
		perror("error when creating socket");
		return (-1);
	}

	// make headers manually included in packet
	int opt;
	if (setsockopt(socketFd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt)) < 0)
	{
		perror("setsockopt IP_HDRINCL error");
		return (-1);
	}

	// get my port and my ip address
	char myIp[16];
	int myPort;
	struct sockaddr_in myAddr;
	memset(myIp, 0, sizeof(myIp));
	socklen_t myAddrLen = sizeof(myAddr);
	getsockname(socketFd, (struct sockaddr*) &myAddr, &myAddrLen); // get my address (the address to which the socket is bound)
	inet_ntop(AF_INET, &myAddr.sin_addr, myIp, sizeof(myIp)); // extract the ip address from the addr
	myPort = ntohs(myAddr.sin_port); // extract portno from addr

	// add neccessary data to the headers in the packet
	cout << "packetLength: " << packetLength << endl;
	populateIPx(ipx, myIp, packetLength);
	populateudpHdrx(udpHdrx, myPort, openPorts[EVILPORT], sizeof(message));

	// test
	socklen_t socklen = sizeof(server_socket_addr);
	sendto(socketFd, packet, packetLength, 0, (sockaddr *)&server_socket_addr, socklen);

	return 1;
}

int main(int argc, char *argv[])
{
	if (argc != 4)
	{
		printf("Usage: ./scanner <ip_address> <low_start> <high_end>\n");
		exit(0);
	}

	ip_address = argv[1];
	low_port = atoi(argv[2]);
	high_port = atoi(argv[3]);

	// initialize the server socket address
	memset(&server_socket_addr, 0, sizeof(server_socket_addr)); // Initialise memory
	server_socket_addr.sin_family = AF_INET;					// pv4
	server_socket_addr.sin_addr.s_addr = inet_addr(ip_address); // bind to server ip

	if (findOpenPorts() > 0)
	{
		cout << "open ports found: " << endl;
		printOpenPorts();
	}

	answerMeTheseRiddlesThree();

	return 0;
}
