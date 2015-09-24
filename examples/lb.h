struct compact_eth_hdr {
	unsigned char   h_dest[ETH_ALEN];
	unsigned char   h_source[ETH_ALEN];
	u_int16_t       h_proto;
};

struct compact_ip_hdr {
	u_int8_t ihl:4,
	         version:4;
	u_int8_t tos;
	u_int16_t tot_len;
	u_int16_t id;
	u_int16_t frag_off;
	u_int8_t ttl;
	u_int8_t protocol;
	u_int16_t check;
	u_int32_t saddr;
	u_int32_t daddr;
};

struct compact_ipv6_hdr {
	u_int8_t priority:4,
	         version:4;
	u_int8_t flow_lbl[3];
	u_int16_t payload_len;
	u_int8_t nexthdr;
	u_int8_t hop_limit;
	struct in6_addr saddr;
	struct in6_addr daddr;
};
