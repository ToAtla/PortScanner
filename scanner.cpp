//
// Simple scanner application for Project 2 TSAM-409
//
// Author: thorduratl17@ru.is and thordurf17@ru.is
//
// Build on macOS: g++ -std=c++11 client.cpp -o client
//
// Based on Code copied from https://www.geeksforgeeks.org/socket-programming-cc/
#include <stdio.h>
#include <iostream>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char const *argv[])
{
	if(argc != 4)
	{
			printf("Usage: ./scanner <ip_address> <low_start> <high_end>\n");
			exit(0);
	}
 	const char* ip_address = argv[1];
	int low_port = atoi(argv[2]);
	int high_port = atoi(argv[3]);

	printf("No ports were scanned\n");

	return 0;
}
