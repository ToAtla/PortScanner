#include <iostream>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>

using namespace std;

int high_port;
int low_port;
char *ip_address;
struct sockaddr_in server_socket_addr; // address of server
const int OPENPORTCOUNT = 4;
int openPorts[OPENPORTCOUNT];
int hiddenPorts[2];
int portGivenByEz;

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
				if (portIndex < 0) {
					perror("could not determine open port");
					return (-1);
				} 
				openPorts[portIndex] = portno;

				// extract the port that is given by the "ez port"
				if (portIndex == EZPORT) {
					int beginIndex = responseString.find(":") + 1;  
					portGivenByEz = atoi(responseString.substr(beginIndex).c_str());
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

	return 0;
}