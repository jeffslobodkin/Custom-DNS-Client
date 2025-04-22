// Jeffrey Slobodkin
// CSCE 463 Fall 2024
// UIN: 532002090

#pragma pack(push,1) 
struct DNSanswerHdr {
	unsigned short type;
	unsigned short class_name;
	unsigned int ttl;
	unsigned short len;
};
#pragma pack(pop)