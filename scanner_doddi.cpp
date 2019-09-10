#include <iostream>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>

using namespace std;

int scan_ports(char* ip_address, int low_port, int high_port)
{
	// TODO: what is ther difference between socket_raw and sock_dgram and which should we use?
	// TODO: why are we using udp instead of tcp?
	int socketfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (socketfd < 0)
    {
        perror("Failed to open socket");
        return (-1);
    }

	struct sockaddr_in server_socket_addr;  					// address of server
	memset(&server_socket_addr, 0, sizeof(server_socket_addr)); // Initialise memory
	server_socket_addr.sin_family = AF_INET;                    // pv4
    server_socket_addr.sin_addr.s_addr = inet_addr(ip_address); // bind to server ip

	// iterate through each portnumber in the range given
	for (int portno = low_port; portno <= high_port; portno++) {
		server_socket_addr.sin_port = htons(portno); // portnumber

		// connect to server
		if (connect(socketfd, (struct sockaddr *)&server_socket_addr, sizeof(server_socket_addr)) < 0)
		{
			cout << "failed to connect to server on port: " << portno << endl;
		}


	}

	return 1;


}

int main(int argc, char *argv[])
{
	if(argc != 4)
	{
		printf("Usage: ./scanner <ip_address> <low_start> <high_end>\n");
		exit(0);
	}
 	
 	char* ip_address = argv[1];
	int low_port = atoi(argv[2]);
	int high_port = atoi(argv[3]);
	
	if (scan_ports(ip_address, low_port, high_port) < 0) {

	};

	return 0;
}