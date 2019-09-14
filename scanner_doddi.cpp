#include <iostream>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>
#include "ipx.h"
#include "checksums.h"

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
	// string source_ip_address = "10.0.2.15";
	string source_ip_address = "172.30.1.9";
	printf("Hardcoded source IP is: %s", source_ip_address.c_str());
	return source_ip_address;
}

// Modified from: https://www.binarytides.com/tcp-syn-portscan-in-c-with-linux-sockets/
struct in_addr get_local_address()
{
	char buffer[1024];
	memset(buffer, 0, sizeof(buffer));

	int sock = socket(AF_INET, SOCK_DGRAM, 0);

	const char *kGoogleDnsIp = "8.8.8.8";
	int dns_port = 53;

	struct sockaddr_in serv;

	memset(&serv, 0, sizeof(serv));
	serv.sin_family = AF_INET;
	serv.sin_addr.s_addr = inet_addr(kGoogleDnsIp);
	serv.sin_port = htons(dns_port);

	connect(sock, (const struct sockaddr *)&serv, sizeof(serv));

	struct sockaddr_in name;
	socklen_t namelen = sizeof(name);
	getsockname(sock, (struct sockaddr *)&name, &namelen);
	close(sock);

	return name.sin_addr;
}

void populateIPx(struct IPx *ipx, char *myIp, char *packet, short packetLength)
{
	ipx->ihl = 5;				 // header length: 20 B which is 5 32-bit words
	ipx->version = 4;			 // ipv4
	ipx->tot_len = packetLength; // total length of packet
	ipx->id = 0x00ff;			 // just some identification
	ipx->frag_off = 0x0000;
	ipx->ttl = 0xFF;			 // time to live as much as possible
	ipx->protocol = IPPROTO_UDP; // set to udp protocol
	ipx->check = csum((unsigned short *)packet, ipx->tot_len >> 1);
	ipx->saddr = inet_addr(myIp);
	ipx->daddr = inet_addr(ip_address);
}

void populateudpHdrx(struct udpHdrx *udphdrx, int myPortNo, int messageSize)
{
	udphdrx->source = htons(myPortNo);
	udphdrx->dest = htons(0);									// set this later
	udphdrx->len = htons(sizeof(struct udpHdrx) + messageSize); // length of udp header + udp data
	udphdrx->check = 0;
}

int evilPuzzle(struct IPx *ipx, udpHdrx *udphdrx, int socketFd, int recvSocket, char *packet, int packetLength)
{
	// change what is specifically for this puzzle
	ipx->frag_off = htons(0x8000);							  // set evil bit
	server_socket_addr.sin_port = htons(openPorts[EVILPORT]); // set port nr
	udphdrx->dest = htons(openPorts[EVILPORT]);				  // set port nr

	socklen_t socklen = sizeof(server_socket_addr);
	// send udp message to evil port
	if (sendto(socketFd, packet, packetLength, 0, (sockaddr *)&server_socket_addr, socklen) < 0)
	{
		perror("Evil bit message sending failed.");
		return -1;
	}

	int responseSize = 128;
	char response[128];
	recvfrom(recvSocket, response, responseSize, 0, (sockaddr *)&server_socket_addr, &socklen);

	// extract the port
	string responseString(response);
	int beginIndex = responseString.find("\n") + 1;
	int returnPort = atoi(responseString.substr(beginIndex).c_str());

	return returnPort;
}

int checksumPuzzle(struct IPx *ipx, udpHdrx *udphdrx, int socketFd, int recvSocket, char *packet, char *message, int packetLength)
{
	server_socket_addr.sin_port = htons(openPorts[CHECKSUMPORT]); // set port nr
	udphdrx->dest = htons(openPorts[CHECKSUMPORT]);				  // set port nr
	ipx->frag_off = 0x0000;										  // dont want evil puzzle to have evil influence
	udphdrx->check = calculate_udp_checksum(udphdrx, ipx, message, strlen(message));


	socklen_t socklen = sizeof(server_socket_addr);
	sendto(socketFd, packet, packetLength, 0, (sockaddr *)&server_socket_addr, socklen);

	int responseSize = 128;
	char response[128];
	recvfrom(recvSocket, response, responseSize, 0, (sockaddr *)&server_socket_addr, &socklen);

	cout << response << endl;

	return 1;
}

/*
solve the three puzzle ports to get the 2 hidden ports
1. "This is the port:xxxx"
2. "I only speak with fellow evil villains. (https://en.wikipedia.org/wiki/Evil_bit)"
3. "Please send me a message with a valid udp checksum with value of xxxxx"
*/
char random_char()
{
	int lim = 90;
	int min = 33;
	return min + random() % lim;
}

// when you call this function make indexAt = 0, bottom be the messageSize-1, gotit is false, dataptr is data
void recursionThing(int indexAt, char *message, int bottom, struct IPx *ipx, udpHdrx *udphdrx, char *packet, char *dataptr, bool gotIt)
{
	if (indexAt > bottom || gotIt)
	{
		return;
	}
	int originalValue = message[indexAt];
	for (int i = originalValue; i <= 127; i++)
	{
		message[indexAt] = i;
		if (indexAt == bottom)
		{
			//strcpy(dataptr, message);
			//
			//udphdrx->dest = htons(openPorts[CHECKSUMPORT]); // set port nr
			//ipx->frag_off = 0x0000;							// dont want evil puzzle to have evil influence
			//
			//unsigned short check = htons(calculate_udp_checksum(udphdrx, ipx, message, sizeof(message)));
			//cout << "message: " << message << " : " << check << endl;
			//if (checksumGivenByPort == check)
			//{
			//	cout << "gots it: " << message << endl;
			//	gotIt = true;
			//}
		}
		else
		{
			recursionThing(indexAt + 1, message, bottom, ipx, udphdrx, packet, dataptr, gotIt);
		}
	}
	message[indexAt] = 0;
	return;
}

int answerMeTheseRiddlesThree()
{
	// first lets do the checksum puzzle
	struct IPx *ipx;
	struct udpHdrx *udphdrx;
	char *data;
	// TODO cannot be longer than 20 Bytes, otherwise the checksum will be incorrect
	//char possible_message1[] = "cu<2/3>";
	//char possible_message2[] = "`Ur[8d8uYfR";
	char message[] = "cu<2/3>";
	//printf("Trying message: %s\n", message);

	short packetLength = sizeof(struct IPx) + sizeof(struct udpHdrx) + strlen(message);

	// TODO: how big should this be?
	char packet[packetLength];
	memset(packet, 0, sizeof(packet));

	// make pointers point to where they should point on the packet
	ipx = (IPx *)packet;
	udphdrx = (udpHdrx *)(packet + sizeof(struct IPx));
	data = (char *)(packet + sizeof(struct IPx) + sizeof(struct udpHdrx));

	// write the message into its appropriate place within the packet
	strcpy(data, message);

	// raw socket without andy protocol header
	int socketFd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (socketFd < 0)
	{
		perror("error when creating socket\n");
		return (-1);
	}

	// make headers manually included in packet
	int opt = 1;
	if (setsockopt(socketFd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt)) < 0)
	{
		perror("setsockopt IP_HDRINCL error\n");
		return (-1);
	}

	// get my port and my ip address
	char myIp[16];
	struct in_addr local_ip = get_local_address();
	inet_ntop(AF_INET, &local_ip, myIp, sizeof(myIp));
	int myPort = 39123;

	// my_addr to bind to socket
	struct sockaddr_in my_addr;
	my_addr.sin_family = AF_INET;
	my_addr.sin_addr.s_addr = inet_addr(myIp);
	my_addr.sin_port = htons(myPort);

	// new socket to receive from the server.
	int recvSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	bind(recvSocket, (struct sockaddr *)&my_addr, sizeof(my_addr));

	// add neccessary data to the headers in the packet
	populateIPx(ipx, myIp, packet, packetLength);
	populateudpHdrx(udphdrx, myPort, strlen(message));

	int bla = evilPuzzle(ipx, udphdrx, socketFd, recvSocket, packet, packetLength);
	cout << "port from evil port " << bla << endl;

	checksumPuzzle(ipx, udphdrx, socketFd, recvSocket, packet, message, packetLength);

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
	//openPorts[0] = 0;
	//openPorts[1] = 4001;
	//openPorts[2] = 4042;
	//openPorts[3] = 0;
	answerMeTheseRiddlesThree();

	return 0;
}
