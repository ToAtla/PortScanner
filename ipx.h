//
// IP and UDP header structs taken from https://unix.superglobalmegacorp.com/Net2/newsrc/netinet/ip.h.html
//
// Added here to enforce consistency and compatability between Linux and OSX
struct IPx {
    #if BYTE_ORDER == LITTLE_ENDIAN
    	u_char	ihl:4,		/* header length */
    		version:4;			/* version */
    #endif
    #if BYTE_ORDER == BIG_ENDIAN
    	u_char version:4,			/* version */
    		ihl:4;		/* header length */
    #endif
    	u_char	tos;			/* type of service */
    	short	tot_len;			/* total length */
    	u_short	id;			/* identification */
    	short	frag_off;			/* fragment offset field */
	#define EVIL_BIT 0x8000 			/* evil bit */
    #define	IP_DF 0x4000			/* dont fragment flag */
    #define	IP_MF 0x2000			/* more fragments flag */
    	u_char	ttl;			/* time to live */
    	u_char	protocol;			/* protocol */
    	u_short	check;			/* checksum */
      __uint32_t saddr, daddr;	/* source and dest address */
};

struct udpHdrx {
	u_short	source;		/* source port */
	u_short	dest;		/* destination port */
	u_short	len;		/* udp length */
	u_short	check;			/* udp checksum */
};


// Here are both original versions for reference:


// Linux

/*
struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	ihl:4,
		version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u8	version:4,
  		ihl:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	__u8	tos;
	__be16	tot_len;
	__be16	id;
	__be16	frag_off;
	__u8	ttl;
	__u8	protocol;
	__sum16	check;
	__be32	saddr;
	__be32	daddr;
};
*/

// OSX

// struct ipx {
//     #if BYTE_ORDER == LITTLE_ENDIAN
//     	u_char	ip_hl:4,		/* header length */
//     		ip_v:4;			/* version */
//     #endif
//     #if BYTE_ORDER == BIG_ENDIAN
//     	u_char	ip_v:4,			/* version */
//     		ip_hl:4;		/* header length */
//     #endif
//     	u_char	ip_tos;			/* type of service */
//     	short	ip_len;			/* total length */
//     	u_short	ip_id;			/* identification */
//     	short	ip_off;			/* fragment offset field */
//     #define	IP_DF 0x4000			/* dont fragment flag */
//     #define	IP_MF 0x2000			/* more fragments flag */
//     	u_char	ip_ttl;			/* time to live */
//     	u_char	ip_p;			/* protocol */
//     	u_short	ip_sum;			/* checksum */
//     	struct	in_addr ip_src,ip_dst;	/* source and dest address */
// };
