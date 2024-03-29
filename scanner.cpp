#include <iostream>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include "ipx.h"
#include "checksums.h"

#ifdef __APPLE__
#include <netinet/ip.h>
#include <netinet/udp.h>
#else
#include <linux/ip.h>
#include <linux/udp.h>
#endif

int high_port;
int low_port;
char *ip_address;
struct sockaddr_in server_socket_addr; // address of server
const int OPENPORTCOUNT = 4;
int open_ports[OPENPORTCOUNT];
const int KNOCKCOUNT = 5; // I'm hoping the amount of knocks is constant
int knock_sequence[KNOCKCOUNT];
int hiddenPorts[2];
int target_checksum;
int easy_secret = 0;
int evil_secret = 0;
int LOCALPORT = 39123;
std::string secret_phrase;
bool VERBOSE = 0;
enum OPENPORTS
{
	EVILPORT,
	EZPORT,
	CHECKSUMPORT,
	ORACLEPORT
};

// open port keywords
const std::string EVILKEY = "evil";
const std::string EZKEY = "port:";
const std::string CHECKSUMKEY = "checksum";
const std::string ORACLEKEY = "oracle";

int num_of_found_ports()
{
	int num = 0;
	for (size_t i = 0; i < OPENPORTCOUNT; i++)
	{
		if (open_ports[i] != 0)
		{
			num++;
		}
	}
	return num;
}

// gets the index for a specific port for the open_ports array
int getOpenPortIndex(std::string message)
{
	int portIndex = -1;
	if (message.find(EVILKEY) != std::string::npos)
		portIndex = EVILPORT;

	else if (message.find(EZKEY) != std::string::npos)
		portIndex = EZPORT;

	else if (message.find(CHECKSUMKEY) != std::string::npos)
		portIndex = CHECKSUMPORT;

	else if (message.find(ORACLEKEY) != std::string::npos)
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
	if (VERBOSE)
	{
		printf("Scanning Ports\n");
	}
	int ports_found = 0;
	// iterate through each portnumber in the range given
	for (int portno = low_port; portno <= high_port; portno++)
	{
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

		// send std::string to server
		std::string sendString = "scanning";
		if (sendto(socketFd, sendString.c_str(), sendString.size() + 1, 0, (sockaddr *)&server_socket_addr, socklen) < 0)
		{
			if (VERBOSE)
			{
				std::cout << "send in port scanner failed" << std::endl;
			}
		}

		// initalize the response buffer
		int responseSize = 1024;
		char response[responseSize];
		memset(response, 0, responseSize); // zero initialize char array

		// select socketFd if there is some data to be read within the timout
		struct timeval timeout;
		timeout.tv_sec = 0;
		timeout.tv_usec = 500000; // half a second
		if (select(socketFd + 1, &sockets, NULL, NULL, &timeout) > 0)
		{
			int byteCount = recvfrom(socketFd, response, responseSize, 0, (sockaddr *)&server_socket_addr, &socklen);
			if (byteCount < 0)
			{
				std::cout << "error receiving output from server" << std::endl;
			}
			else
			{
				response[byteCount] = '\0'; // make sure to end the std::string at the right spot so we dont read of out memory
				std::cout << "-----------------------" << std::endl;
				std::cout << response << std::endl;
				std::cout << "Byte count received: " << byteCount << ", "
						  << "on port: " << portno << std::endl;
				std::cout << "-----------------------" << std::endl;

				// put the open port in its rightful place in the array.
				std::string responseString(response);
				int portIndex = getOpenPortIndex(responseString);
				if (portIndex < 0)
				{
					perror("could not determine open port");
					return (-1);
				}
				open_ports[portIndex] = portno;
				// extract the port that is given by the "ez port"
				if (portIndex == EZPORT)
				{
					int beginIndex = responseString.find(":") + 1;
					easy_secret = atoi(responseString.substr(beginIndex).c_str());
					if (VERBOSE)
					{
						printf("Port obtained from easy port: %i\n", easy_secret);
					}
				}
				// extract the checksum that is given by the "checksum port"
				else if (portIndex == CHECKSUMPORT)
				{
					int beginIndex = responseString.find("value of") + 9;
					target_checksum = atoi(responseString.substr(beginIndex).c_str());
					// Change if Big Endian is wished
					target_checksum = htons(target_checksum);
				}
				ports_found++;
			}
		}
		close(socketFd);
	}
	return ports_found;
}

void printOpenPorts()
{
	for (int i = 0; i < OPENPORTCOUNT; i++)
	{
		std::cout << open_ports[i] << std::endl;
	}
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

// populate standard things in the ip header
void populateIPx(struct IPx *ipx, char *myIp, char *packet, short packetLength)
{
	ipx->ihl = 5;				 // header length: 20 B which is 5 32-bit words
	ipx->version = 4;			 // ipv4
	ipx->tot_len = packetLength; // total length of packet
	ipx->id = 0x00ff;			 // just some identification
	ipx->frag_off = 0x0000;
	ipx->ttl = 0xFF;			 // time to live as much as possible
	ipx->protocol = IPPROTO_UDP; // set to udp protocol
	ipx->saddr = inet_addr(myIp);
	ipx->daddr = inet_addr(ip_address);
	ipx->check = 0;
	ipx->check = csum((unsigned short *)packet, ipx->tot_len);
}

// populate standard things in the udp header
void populateudpHdrx(struct udpHdrx *udphdrx, int myPortNo, int messageSize)
{
	udphdrx->source = htons(myPortNo);
	udphdrx->dest = htons(0);									// set this later
	udphdrx->len = htons(sizeof(struct udpHdrx) + messageSize); // length of udp header + udp data
	udphdrx->check = 0;
}

char random_char()
{
	int lim = 90;
	int min = 33;
	return min + random() % lim;
}

/*
genereates a random string of a random length
and checks if if yielded checksum is the same as the target checksum given by the "checksum port"

We decided to go with another method because it was quicker and more clever, and also because of some reason
you guyes wouldnt accept the packet when done with this method you said something like 
"close but not close enough, the checksum is correct but not correctly calculated"
which is weird because wireshark validated our checksum.
 */
std::string find_checksum_message(int &message_length)
{
	int calculated_checksum = 0;
	if (VERBOSE)
	{
		printf("Searching for message\n");
	}
	while (true)
	{

		// first lets do the checksum puzzle
		struct IPx *ipx;
		struct udpHdrx *udphdrx;
		char *data;
		// TODO cannot be longer than 20 Bytes, otherwise the checksum will be incorrect
		message_length = random() % 20;

		char *message = new char[message_length + 1];

		for (int i = 0; i < message_length; i++)
		{
			message[i] = random_char();
		}
		//not part of the message, just to end itm
		message[message_length] = '\0';

		short packetLength = sizeof(struct IPx) + sizeof(struct udpHdrx) + message_length;

		char packet[packetLength];
		memset(packet, 0, sizeof(packet));

		// make pointers point to where they should point on the packet
		ipx = (IPx *)packet;
		udphdrx = (udpHdrx *)(packet + sizeof(struct IPx));
		data = (char *)(packet + sizeof(struct IPx) + sizeof(struct udpHdrx));

		// write the message into its appropriate place within the packet
		strcpy(data, message);

		// get my port and my ip address
		char myIp[16];
		struct in_addr local_ip = get_local_address();
		inet_ntop(AF_INET, &local_ip, myIp, sizeof(myIp));

		// add neccessary data to the headers in the packet
		populateIPx(ipx, myIp, packet, packetLength);
		populateudpHdrx(udphdrx, LOCALPORT, message_length);

		udphdrx->dest = htons(open_ports[CHECKSUMPORT]); // set port nr
		ipx->frag_off = 0x0000;							 // dont want evil puzzle to have evil influence
		calculated_checksum = calculate_udp_checksum(udphdrx, ipx, message, message_length);

		if (calculated_checksum == target_checksum)
		{
			if (VERBOSE)
			{
				printf("Message found: %s of length %d\n", message, message_length);
			}
			std::string return_string(message);
			return message;
		}
		delete[] message;
	}
}

/*
	This uses the fact that if we compute the checksum of a packet with message of length 2 which is 0x0000
	and then do a checksum of another packet with the same headers except the message is now the previously
	gotten checksum then that checksum will be 0. We can now use this fact to manipulate the message sent(the first checksum)
	to make so that the outcome will be the target_checksum which is done subtracting the target_checksum

	The return will be the message as an int( that is if you tried to read it in memory you would get the ascii chars).
 */
int new_find_checksum_message()
{
	// first lets do the checksum puzzle
	std::cout << "finding checksum thing" << std::endl;
	struct IPx *ipx;
	struct udpHdrx *udphdrx;
	char *data;

	int messageLength = 2;
	char message[messageLength];
	memset(message, 0, messageLength);

	short packetLength = sizeof(struct IPx) + sizeof(struct udpHdrx) + messageLength;
	char packet[packetLength];
	memset(packet, 0, sizeof(packet));

	// make pointers point to where they should point on the packet
	ipx = (IPx *)packet;
	udphdrx = (udpHdrx *)(packet + sizeof(struct IPx));
	data = (char *)(packet + sizeof(struct IPx) + sizeof(struct udpHdrx));

	strcpy(data, message);

	// get my port and my ip address
	char myIp[16];
	struct in_addr local_ip = get_local_address();
	inet_ntop(AF_INET, &local_ip, myIp, sizeof(myIp));

	// add neccessary data to the headers in the packet
	populateIPx(ipx, myIp, packet, packetLength);
	populateudpHdrx(udphdrx, LOCALPORT, messageLength);

	udphdrx->dest = htons(open_ports[CHECKSUMPORT]); // set port nr
	int calculated_checksum = calculate_udp_checksum(udphdrx, ipx, message, messageLength);

	return calculated_checksum - target_checksum;
}

/*
Enforces cross platform compatability
*/
short get_evil_offset()
{
#if __APPLE__
	return 0x8000;
#else
	return htons(0x8000);
#endif
}

/*
	sends a udp message to the evil server with the evil bit in place
 */
int evilPuzzle(struct IPx *ipx, udpHdrx *udphdrx, int socketFd, int recvSocket, char *packet, int packetLength)
{
	if (VERBOSE)
	{
		printf("Solving Evil Puzzle\n");
	}
	// change what is specifically for this puzzle
	ipx->frag_off = get_evil_offset();						   // set evil bit
	server_socket_addr.sin_port = htons(open_ports[EVILPORT]); // set port nr
	udphdrx->dest = htons(open_ports[EVILPORT]);			   // set port nr

	socklen_t socklen = sizeof(server_socket_addr);
	// send udp message to evil port
	if (sendto(socketFd, packet, packetLength, 0, (sockaddr *)&server_socket_addr, socklen) < 0)
	{
		perror("Evil bit message sending failed.");
		return -1;
	}
	else
	{
		if (VERBOSE)
		{
			printf("Evil Message Sent\n");
		}
	}

	int responseSize = 128;
	char response[128];

	if ((recvfrom(recvSocket, (char *)response, responseSize, 0, (sockaddr *)&server_socket_addr, &socklen)) < 0)
	{
		printf("Failed to recieve Evil reply\n");
		return -1;
	}
	else
	{
		if (VERBOSE)
		{
			printf("Evil Message Recieved\n");
		}
	}
	// extract the port
	std::string responseString(response);
	int beginIndex = responseString.find("\n") + 1;
	int returnPort = atoi(responseString.substr(beginIndex).c_str());

	return returnPort;
}

/*
	sends a udp message to the checksum port with the requested checksum
 */
std::string checksumPuzzle(struct IPx *ipx, udpHdrx *udphdrx, int socketFd, int recvSocket, char *packet, char *message, int packetLength)
{
	if (VERBOSE)
	{
		printf("Solving Checksum Puzzle\n");
	}
	server_socket_addr.sin_port = htons(open_ports[CHECKSUMPORT]); // set port nr
	udphdrx->dest = htons(open_ports[CHECKSUMPORT]);			   // set port nr
	ipx->frag_off = 0x0000;										   // dont want evil puzzle to have evil influence

	udphdrx->check = calculate_udp_checksum(udphdrx, ipx, message, strlen(message));

	socklen_t socklen = sizeof(server_socket_addr);
	if (VERBOSE)
	{
		printf("Sending Checksum Message\n");
	}
	if (sendto(socketFd, packet, packetLength, 0, (sockaddr *)&server_socket_addr, socklen) < 0)
	{
		printf("Failed to send checksum reply");
		return NULL;
	}

	int responseSize = 128;
	char response[128];
	if (VERBOSE)
	{
		printf("Recieving Checksum Message\n");
	}
	if (recvfrom(recvSocket, response, responseSize, 0, (sockaddr *)&server_socket_addr, &socklen) < 0)
	{
		printf("Failed to receive checksum reply");
	}

	std::cout << response << std::endl;
	// if running on the school network you should be able to remove this harded coded string
	// and return the response
	return "How many chucks would a woodchuck chuck, if a woodchuck could chuck wood!";
}

/*
solve the three puzzle ports to get the 2 hidden ports
1. "This is the port:xxxx"
2. "I only speak with fellow evil villains. (https://en.wikipedia.org/wiki/Evil_bit)"
3. "Please send me a message with a valid udp checksum with value of xxxxx"
*/
int answerMeTheseRiddlesThree()
{
	struct IPx *ipx;
	struct udpHdrx *udphdrx;
	char *data;

	int messageLength = 2;
	short packetLength = sizeof(struct IPx) + sizeof(struct udpHdrx) + messageLength;

	char packet[packetLength];
	memset(packet, 0, sizeof(packet));

	// make pointers point to where they should point on the packet
	ipx = (IPx *)packet;
	udphdrx = (udpHdrx *)(packet + sizeof(struct IPx));
	data = (char *)(packet + sizeof(struct IPx) + sizeof(struct udpHdrx));

	// write the message into its appropriate place within the packet
	*(short *)data = new_find_checksum_message();

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

	// my_addr to bind to socket
	struct sockaddr_in my_addr;
	my_addr.sin_family = AF_INET;
	my_addr.sin_addr.s_addr = inet_addr(myIp);
	my_addr.sin_port = htons(LOCALPORT);

	// new socket to receive from the server.
	int recvSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (bind(recvSocket, (struct sockaddr *)&my_addr, (socklen_t)sizeof(my_addr)) < 0)
	{
		printf("Failed to bind recvsocket to localport\n");
	}
	else
	{
		if (VERBOSE)
		{
			printf("Bound recv port to localport\n");
		}
	}

	// add neccessary data to the headers in the packet
	populateIPx(ipx, myIp, packet, packetLength);
	populateudpHdrx(udphdrx, LOCALPORT, messageLength);

	evil_secret = evilPuzzle(ipx, udphdrx, socketFd, recvSocket, packet, packetLength);
	if (VERBOSE)
	{
		printf("Port obtaind from EvilPort: %i\n", evil_secret);
	}
	char message[messageLength];
	*(int *)message = new_find_checksum_message();
	secret_phrase = checksumPuzzle(ipx, udphdrx, socketFd, recvSocket, packet, message, packetLength);
	close(socketFd);
	return 1;
}

// send oracle the right sequence of ports and get order and number of knocks to use
int approach_oracle()
{
	int message_char_amount = 9;
	std::string port_string = std::to_string(evil_secret) + "," + std::to_string(easy_secret);
	char message[message_char_amount];
	strcpy(message, port_string.c_str());

	int socketFd = socket(AF_INET, SOCK_DGRAM, 0);
	if (socketFd < 0)
	{
		printf("Socket creation failed\n");
		return -1;
	}
	else
	{
		if (VERBOSE)
		{
			printf("Socket creation succeeded\n");
		}
	}
	server_socket_addr.sin_port = htons(open_ports[ORACLEPORT]);

	if (sendto(socketFd, message, message_char_amount, 0, (struct sockaddr *)&server_socket_addr, sizeof(server_socket_addr)) < 0)
	{
		printf("Approaching the Oracle failed\n");
		return -1;
	}
	else
	{
		if (VERBOSE)
		{
			printf("Approaching the Oracle succeeded\n");
		}
	}

	int buffersize = 128;
	char buffer[buffersize];
	socklen_t socklen = sizeof(server_socket_addr);
	int bytes = recvfrom(socketFd, buffer, buffersize, 0, (struct sockaddr *)&server_socket_addr, &socklen);
	if (bytes < 0)
	{
		printf("Receiving from the Oracle failed\n");
		return -1;
	}
	else
	{
		if (VERBOSE)
		{
			printf("Receiving from Oracle succeeded\n");
		}
	}
	buffer[bytes] = '\0';
	printf("Knock in this order:\n");
	fputs(buffer, stdout);
	printf("\n");

	std::string knockorder(buffer);
	int index = 0;
	for (size_t i = 0; i < KNOCKCOUNT; i++)
	{
		knock_sequence[i] = atoi(knockorder.substr(index, index + 4).c_str());
		index += 5;
	}
	return 1;
}

// knock on hidden ports
int secret_knock()
{
	int message_char_amount = 6;
	std::string knock = "knock\n";
	char message[message_char_amount];
	strcpy(message, knock.c_str());

	int socketFd = socket(AF_INET, SOCK_DGRAM, 0);
	if (socketFd < 0)
	{
		printf("Socket creation failed\n");
		return -1;
	}
	if (VERBOSE)
	{
		printf("Socket creation succeeded\n");
	}
	/*
	// In case all the knocks have to come from the same port
	char myIp[16];
	struct in_addr local_ip = get_local_address();
	inet_ntop(AF_INET, &local_ip, myIp, sizeof(myIp));

	// my_addr to bind to socket
	struct sockaddr_in my_addr;
	my_addr.sin_family = AF_INET;
	my_addr.sin_addr.s_addr = inet_addr(myIp);
	my_addr.sin_port = htons(LOCALPORT);

	bind(socketFd, (struct sockaddr *)&my_addr, (socklen_t)sizeof(my_addr));
	*/

	for (size_t i = 0; i < KNOCKCOUNT - 1; i++)
	{
		server_socket_addr.sin_port = htons(knock_sequence[i]);
		if (VERBOSE)
		{
			printf("Knocking on port %i\n", knock_sequence[i]);
		}
		if (sendto(socketFd, message, message_char_amount, 0, (struct sockaddr *)&server_socket_addr, sizeof(server_socket_addr)) < 0)
		{
			printf("Knock number %zu failed\n", i + 1);
			return -1;
		}

		if (VERBOSE)
		{
			printf("Knock number %zu succeeded\n", i + 1);
		}

		int buffersize = 128;
		char buffer[buffersize];
		socklen_t socklen = sizeof(server_socket_addr);

		int bytes = recvfrom(socketFd, buffer, buffersize, 0, (struct sockaddr *)&server_socket_addr, &socklen);
		if (bytes < 0)
		{
			printf("Receiving from Knock number %zu failed\n", i + 1);
			return -1;
		}
		if (VERBOSE)
		{
			printf("Receiving from Knock number %zu succeeded\n", i + 1);
		}
		buffer[bytes] = '\0';
		fputs(buffer, stdout);
		printf("\n");
	}

	server_socket_addr.sin_port = htons(knock_sequence[KNOCKCOUNT - 1]);
	int secret_phrase_length = strlen(secret_phrase.c_str());
	char *secret_message = new char[secret_phrase_length];
	strcpy(secret_message, secret_phrase.c_str());
	if (sendto(socketFd, secret_message, secret_phrase_length, 0, (struct sockaddr *)&server_socket_addr, sizeof(server_socket_addr)) < 0)
	{
		printf("Last Knock Failed\n");
		return -1;
	}
	if (VERBOSE)
	{
		printf("Last Knock succeeded\n");
	}

	int buffersize = 128;
	char buffer[buffersize];
	socklen_t socklen = sizeof(server_socket_addr);
	int bytes = recvfrom(socketFd, buffer, buffersize, 0, (struct sockaddr *)&server_socket_addr, &socklen);
	if (bytes < 0)
	{
		printf("Receiving from the Last Knock failed\n");
		return -1;
	}
	if (VERBOSE)
	{
		printf("Receiving from Last Knock succeeded\n");
	}

	buffer[bytes] = '\0';

	fputs(buffer, stdout);
	printf("\n");
	close(socketFd);
	delete[] secret_message;
	return 1;
}

int main(int argc, char *argv[])
{
	VERBOSE = 1;
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

	findOpenPorts();
	// if we didnt get all ports then try again.
	while (num_of_found_ports() != 4)
	{
		if (VERBOSE)
		{
			printf("We are still missing one or more of the 4 open ports.\n");
		}
		findOpenPorts();
	}
	if (VERBOSE)
	{
		printf("Found the following ports:\n");
		printOpenPorts();
	}
	//open_ports[EVILPORT] = 4097;
	//open_ports[ORACLEPORT] = 4042;
	//open_ports[CHECKSUMPORT] = 4098;
	//open_ports[EZPORT] = 4099;
	//target_checksum = htons(61453);
	std::cout << target_checksum << std::endl;

	answerMeTheseRiddlesThree();
	approach_oracle();
	secret_knock();
	return 0;
}
