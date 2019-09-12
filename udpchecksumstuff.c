struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t udp_length;
};




short calculate_udp_checksum(struct udpHdrx * udphdrx, struct IPx* ipx, char * message){
	printf("Got this far0");
	struct pseudo_header *psh;
	int pseudegram_length = sizeof(struct pseudo_header) + sizeof(struct udpHdrx) + strlen(message);
	char * pseudogram[pseudegram_length];

	printf("Got this far0");
	psh->source_address = ipx->saddr;
	psh->dest_address = ipx->daddr;
	psh->placeholder = 0;
	psh->protocol = IPPROTO_UDP;
	psh->udp_length = htons(sizeof(struct udpHdrx) + strlen(message));
	printf("Got this far1");
	int psize = sizeof(struct pseudo_header) + sizeof(struct udpHdrx) + strlen(message);
	psh = (pseudo_header *) pseudogram;
	udphdrx = (udpHdrx *) (pseudogram + sizeof(struct pseudo_header));
	message = (char *) (pseudogram + sizeof(struct pseudo_header) + sizeof(struct udpHdrx));
	// memcpy(pseudogram , (char*) psh , sizeof (struct pseudo_header));
	// memcpy(pseudogram + sizeof(struct pseudo_header) , udphdrx , sizeof(struct udpHdrx) + strlen(message));
	printf("Got this far2");
	return csum( (unsigned short*) pseudogram , psize);

	return 0;
}
