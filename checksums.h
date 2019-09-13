struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t udp_length;
};

// From: https://www.binarytides.com/tcp-syn-portscan-in-c-with-linux-sockets/
unsigned short csum(unsigned short *ptr,int nbytes) {
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer = (short)~sum;

    return(answer);
}

void print_packet(char * packet){
	printf("Printing IP header\n");
	for (size_t i = 0; i < sizeof(struct IPx) + sizeof(struct udpHdrx); i++) {
		if(i % 4 == 0) printf("\n");
		unsigned char* current = (unsigned char *) packet + i;
		printf("%x ", *current);
	}
	printf("\n");

}

unsigned short calculate_udp_checksum(struct udpHdrx * udphdrx, struct IPx* ipx, char *message, int message_length){
	int pseudegram_length = sizeof(struct pseudo_header) + sizeof(struct udpHdrx) + sizeof(message);
	char pseudogram[pseudegram_length];
  memset(pseudogram, 0, sizeof(pseudogram));
  struct pseudo_header *psh = (pseudo_header *) pseudogram;
	struct udpHdrx *temp_internal_udphdrx = (udpHdrx *) (pseudogram + sizeof(struct pseudo_header));
	char * temp_internal_message = (char *) (pseudogram + sizeof(struct pseudo_header) + sizeof(struct udpHdrx));
  strcpy(temp_internal_message, message);
  temp_internal_udphdrx->source = udphdrx->source;
  temp_internal_udphdrx->dest = udphdrx->dest;
  temp_internal_udphdrx->len = udphdrx->len;
  temp_internal_udphdrx->check = udphdrx->check;
	psh->source_address = ipx->saddr;
	psh->dest_address = ipx->daddr;
	psh->placeholder = 0;
	psh->protocol = IPPROTO_UDP;
	psh->udp_length = htons(sizeof(struct udpHdrx) + message_length);
	int psize = sizeof(struct pseudo_header) + sizeof(struct udpHdrx) + message_length;

  return csum( (unsigned short*) pseudogram , psize);
}
