//
// Simple scanner application for Project 2 TSAM-409
//
// Author: thorduratl17@ru.is and thordurf17@ru.is
//
#include <iostream>

#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>


#define PORT	4002
#define MAXLINE	1024

struct icmphdr
{
	char type = 0;
	char code = 0;
	short checksum = 0;
	short identifier = 0;
	short sequence_number = 0;
};


void scan_ports()
{
	// socket
	int sockfd = 0;
	int cc = 8;
	struct sockaddr_in servaddr;
	char buffer[MAXLINE];

	struct icmphdr *icp = new icmphdr;
	icp->type = 8; // ICMP_ECHO
	icp->code = 0;
	icp->checksum = 0xfff7; // Hardcoded
	printf("icp created\n");

	if ( (sockfd  = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0 )
	{
		printf("Socket creation failed. Root privilages may be missing.\n");
		return;
	};

	servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(PORT);
	// Converts the IPv4 address from text to binary form
	const char* ip_address = "130.208.243.61";
	if(inet_pton(AF_INET, ip_address , &servaddr.sin_addr)<=0)
	{
		printf("\nInvalid address/ Address not supported \n");
		return;
	}

	int n;
	socklen_t len = sizeof servaddr;

	// sendto
	sendto(sockfd, icp, cc, 0, (const struct sockaddr *) &servaddr, sizeof(servaddr));
  printf("Echo sent.\n");

  // recvfrom
  n = recvfrom(sockfd, (char *)buffer, MAXLINE, MSG_WAITALL, (struct sockaddr *) &servaddr, &len);

  printf("Server : %i bytes recieved\n", n);

  close(sockfd);



}

int main(int argc, char const *argv[])
{
	// Input code
	/*
	if(argc != 4)
	{
			printf("Usage: ./scanner <ip_address> <low_start> <high_end>\n");
			exit(0);
	}
 	const char* ip_address = argv[1];
	int low_port = atoi(argv[2]);
	int high_port = atoi(argv[3]);
	*/

	scan_ports();
	// printf("No ports were scanned\n");

	return 0;
}
