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
#include "icmp.h"
//#include <netinet/ip_icmp.h>
#include <netinet/udp.h>


//#define PORT	4002
#define MAXLINE	1024

const char* ip_address = "130.208.243.61";
const int local_port = 39123;

// Function taken from "Unix Network Programming 2nd Edition Volume 1 - Richard Stevens"
unsigned short in_cksum(unsigned short *addr, int len)
{
  int nleft = len;
  int sum = 0;
  unsigned short *w = addr;
  unsigned short answer = 0;

  /*
   * Our algorithm is simple, using a 32 bit accumulator (sum), we add
   * sequential 16 bit words to it, and at the end, fold back all the
   * carry bits from the top 16 bits into the lower 16 bits.
  */
  while (nleft > 1) {
    sum += *w++;
    nleft -= 2;
  }
    /* mop up an odd byte, if necessary */
  if (nleft == 1){
    *(unsigned char *) (&answer) = *(unsigned char *) w;
    sum += answer;
  }
    /* add back carry outs from top 16 bits to low 16 bits */
  sum = (sum >> 16) + (sum & 0xffff);   /* add hi 16 to low 16*/
  sum += (sum >> 16);     /* add carry */
  answer = ~sum;          /* truncate to 16 bits */
  return (answer);
}


void send_ping(int port)
{
	// socket
	int sockfd = 0;
	int cc = 8;
	struct sockaddr_in servaddr;
	char buffer[MAXLINE];

	struct icmphdr icp;
	int icmp_length = 8; // 8 byte long header with no attached data
	bzero(&icp, sizeof(icp));

	icp.type = ICMP_ECHO;
	icp.code = 0;
	icp.checksum = 0;
	icp.un.echo.id = getpid();
	icp.un.echo.sequence = 0;
	icp.checksum = in_cksum((u_short *) &icp, icmp_length); //0xbff7; // Hardcoded
	printf("icp created\n");

	if ( (sockfd  = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0 )
	{
		printf("Socket creation failed. Root privilages may be missing.\n");
		return;
	};

	servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(port);
	// Converts the IPv4 address from text to binary form

	if(inet_pton(AF_INET, ip_address , &servaddr.sin_addr) <= 0)
	{
		printf("\nInvalid address/ Address not supported \n");
		return;
	}

	// sendto
	sendto(sockfd, &icp, cc, 0, (const struct sockaddr *) &servaddr, sizeof(servaddr));
  printf("Echo sent.\n");

	int n;
	socklen_t len = sizeof servaddr;
  n = recvfrom(sockfd, (char *)buffer, MAXLINE, MSG_WAITALL, (struct sockaddr *) &servaddr, &len);

  printf("Server : %i bytes recieved\n", n);

  close(sockfd);
}

void send_raw_udp(int port){
	int sockfd;
	struct sockaddr_in servaddr;
	char recvline[1025];
  char datagram[1024];
  memset(datagram, 0, 1024);
	char *sendline;
	bzero(&servaddr, sizeof(servaddr));

	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(port);
	if(inet_pton(AF_INET, ip_address , &servaddr.sin_addr) <= 0)
	{
		printf("\nInvalid address/ Address not supported \n");
		return;
	}
	if ( ( sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) < 0 )
	{
		printf("Socket creation failed. Root privilages may be missing.\n");
		return;
	};

	struct udphdr *udph = (struct udphdr *) datagram;

	//bzero(&udph, sizeof(udph));
	udph->uh_sport = htons(local_port);
	udph->uh_dport = htons(port);
  sendline = datagram + sizeof(struct udphdr);
  strcpy(sendline, "Hello");
	udph->uh_ulen = htons(8 + strlen(sendline));
	udph->uh_sum = 0;
  int udp_packet_length = sizeof(struct udphdr) + strlen(sendline);
  if( (sendto(sockfd, udph, udp_packet_length, 0, (const struct sockaddr *) &servaddr, sizeof(servaddr))) < 0)
	{
		printf("Sending failed\n");
		return;
	}
	printf("Sent empty UDP\n");
	socklen_t len = sizeof servaddr;

	int n = recvfrom(sockfd, (char *) recvline, 1024, 0, (struct sockaddr *) &servaddr, &len);
	recvline[n] = '\0';
	printf("Recieved %d bytes\n", n);
	fputs(recvline, stdout);
	/**/
}

void recieve_reply(){
	// recvfrom
	/*

	*/
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

	/*
	for (int i = 4000; i < 4101; i++) {
		send_ping(i);
	}
	*/
	//send_ping(4095);
	send_raw_udp(4026);
	//recieve_reply();
	// printf("No ports were scanned\n");

	return 0;
}
