// Jeffrey Slobodkin
// CSCE 463 Fall 2024
// UIN: 532002090

#pragma once
#ifndef SOCKET_H            
#define SOCKET_H

#define MAX_DNS_LENGTH 512
#define MAX_ATTEMPTS 3
#define A 1
#define NS 2
#define CNAME 5 
#define PTR 12

class Socket {
	private:
		SOCKET sock;
		WSADATA wsaData;
		char buf [MAX_DNS_LENGTH];
		int size;
		char recv_buf[MAX_DNS_LENGTH];

		struct sockaddr_in local_server;
		struct sockaddr_in remote_server;
		char* request;
		char* dns_ip;
		void parseDomainName(char* buf, int bytesReceived, int& cur_pos_buffer, char* result, int& result_index, int jumpCount);

	public:
		Socket(char* request, char* dns_ip);
		~Socket();
		void Send();
		void Bind();
		void CreateBuffer();
		void MakeDNSquestion(const char* request);
		void MakeReverseDNSquestion(const char* ip_address);
		void ProcessReceivedBuffer(char* buf, int bytesReceived);
		std::string MapType(int type);
};
#endif SOCKET_H