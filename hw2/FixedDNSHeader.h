// Jeffrey Slobodkin
// CSCE 463 Fall 2024
// UIN: 532002090

#pragma pack(push,1) 
struct FixedDNSheader {
	unsigned short ID;
	unsigned short flags;
	unsigned short questions;
	unsigned short answers;
	unsigned short authority;
	unsigned short additional;
};
#pragma pack(pop)