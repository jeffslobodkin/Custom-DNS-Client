// Jeffrey Slobodkin
// CSCE 463 Fall 2024
// UIN: 532002090

#include "pch.h"


Socket::Socket(char* request, char* dns_ip) {
	int startup = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (startup != 0) {
		printf("WSAStartup failed: %d\n", startup);
		exit(-1);
	}

	sock = socket(AF_INET, SOCK_DGRAM, 0);

	if (sock == INVALID_SOCKET) {
		printf("socket() error %d\n", WSAGetLastError());
		WSACleanup();
		exit(-1);
	}

	memset(&local_server, 0, sizeof(local_server));
	memset(&remote_server, 0, sizeof(remote_server));

	this->request = request;
	this->dns_ip = dns_ip;
}

void Socket::Bind() {
	local_server.sin_family = AF_INET;
	local_server.sin_addr.s_addr = INADDR_ANY;
	local_server.sin_port = htons(0);

	if (bind(sock, (struct sockaddr*)&local_server, sizeof(local_server)) == SOCKET_ERROR) {
		printf("Failed at binding UDP socket");
		closesocket(sock);
		WSACleanup();
		exit(-1);
	}
}


void Socket::MakeDNSquestion(const char* request) {
	char* context = nullptr;
	char request_copy[256];
	strncpy(request_copy, request, sizeof(request_copy));
	request_copy[sizeof(request_copy) - 1] = '\0';

	char* token = strtok_s(request_copy, ".", &context);
	int curPos = sizeof( );

	while (token != nullptr) {
		int len = strlen(token);
		buf[curPos++] = len;
		memcpy(buf + curPos, token, len);
		curPos += len;
		token = strtok_s(nullptr, ".", &context);
	}
	buf[curPos++] = 0; 

}

void Socket::MakeReverseDNSquestion(const char* ip_address) {
	struct in_addr addr;
	addr.s_addr = inet_addr(ip_address);

	char reverse_ip[64];
	snprintf(reverse_ip, sizeof(reverse_ip), "%u.%u.%u.%u.in-addr.arpa",
		(addr.s_addr >> 24) & 0xFF,
		(addr.s_addr >> 16) & 0xFF,
		(addr.s_addr >> 8) & 0xFF,
		(addr.s_addr) & 0xFF);

	MakeDNSquestion(reverse_ip);
}

void Socket::CreateBuffer() {
	printf("%-10s: %s\n", "Lookup", request);
	std::string original_request(request);
	FixedDNSheader* dh = (FixedDNSheader*)buf;
	QueryHeader* qh;
	srand(time(0));

	dh->ID = htons((unsigned short)(rand() & 0xFFFF));
	dh->flags = htons(0x0100);
	dh->questions = htons(1);
	dh->answers = htons(0);
	dh->authority = htons(0);
	dh->additional = htons(0);

	if (inet_addr(request) == INADDR_NONE) {
		MakeDNSquestion(request);
		size = strlen(request) + 2 + sizeof(FixedDNSheader) + sizeof(QueryHeader);
		qh = (QueryHeader*)(buf + size - sizeof(QueryHeader));
		qh->class_name = htons(1);
		qh->type = htons(1);
		printf("%-10s: %s, type %d, TXID 0x%04X\n", "Query", request, ntohs(qh->type), ntohs(dh->ID));
	}
	else {
		char reverse_ip[64];
		struct in_addr request_addr;
		request_addr.s_addr = inet_addr(request);

		snprintf(reverse_ip, sizeof(reverse_ip), "%u.%u.%u.%u.in-addr.arpa",
			(request_addr.s_addr >> 24) & 0xFF,
			(request_addr.s_addr >> 16) & 0xFF,
			(request_addr.s_addr >> 8) & 0xFF,
			(request_addr.s_addr) & 0xFF);


		MakeReverseDNSquestion(request);
		size = strlen(reverse_ip) + 2 + sizeof(FixedDNSheader) + sizeof(QueryHeader);
		qh = (QueryHeader*)(buf + size - sizeof(QueryHeader));
		qh->class_name = htons(1);
		qh->type = htons(12);

		printf("%-10s: %s, type %d, TXID 0x%04X\n",
			"Query", reverse_ip, ntohs(qh->type), ntohs(dh->ID));

	}

	printf("%-10s: %s\n", "Server", dns_ip);
	printf("********************************\n");
}

void Socket::Send() {
	remote_server.sin_family = AF_INET;
	remote_server.sin_addr.s_addr = inet_addr(dns_ip);
	remote_server.sin_port = htons(53);

	int count = 0;
	timeval timeout;
	timeout.tv_sec = 1;
	timeout.tv_usec = 0;

	while (count++ < MAX_ATTEMPTS) {
		auto start_send = std::chrono::high_resolution_clock::now();
		if (count - 1 > 0) {
			printf("\nAttempt %d with %d bytes... ", count - 1, size);
		}
		else {
			printf("Attempt %d with %d bytes... ", count - 1, size);
		}
		//Send buf over udp
		if (sendto(sock, buf, size, 0, (struct sockaddr*)&remote_server, sizeof(remote_server)) == SOCKET_ERROR) {
			printf("Failed to send the message");
			closesocket(sock);
			WSACleanup();
			exit(-1);
		}

		fd_set readfds;
		FD_ZERO(&readfds);
		FD_SET(sock, &readfds);
		int size_remote = sizeof(remote_server);

		int available = select(0, &readfds, NULL, NULL, &timeout);
		if (available > 0) {
			int received = recvfrom(sock, recv_buf, MAX_DNS_LENGTH, 0, (struct sockaddr*)&remote_server, &size_remote);
			if (received == SOCKET_ERROR) {
				printf("recvfrom() failed with error code : %d", WSAGetLastError());
				closesocket(sock);
				WSACleanup();
				exit(-1);
			}
			auto end_send = std::chrono::high_resolution_clock::now();
			auto duration_send = std::chrono::duration_cast<std::chrono::milliseconds>(end_send - start_send);
			printf("response in %d ms with %d bytes\n", duration_send, received);
			if (received < sizeof(FixedDNSheader)) {
				printf("++ %-3s invalid reply: packet smaller than fixed DNS header", " ");
				exit(-1);
			}
			ProcessReceivedBuffer(recv_buf, received);
			break;
		}
	}
}


void Socket::ProcessReceivedBuffer(char* buf, int bytesReceived) {
	FixedDNSheader* received_header = (FixedDNSheader*)buf;



	received_header->ID = ntohs(*(unsigned short*)buf);
	received_header->flags = ntohs(*(unsigned short*)(buf + 2));
	received_header->questions = ntohs(*(unsigned short*)(buf + 4));
	received_header->answers = ntohs(*(unsigned short*)(buf + 6));
	received_header->authority = ntohs(*(unsigned short*)(buf + 8));
	received_header->additional = ntohs(*(unsigned short*)(buf + 10));
	printf("%-3s TXID 0x%04X flags 0x%04X questions %d answers %d authority %d additional %d\n", " ", received_header->ID, received_header->flags, received_header->questions, received_header->answers, received_header->authority, received_header->additional);

	if (received_header->ID != ntohs(*(unsigned short*)(this->buf))) {
		printf("%-3s ++ invalid reply: TXID mismatch, sent 0x%04X, received 0x%04X", " ", ntohs(*(unsigned short*)(this->buf)), received_header->ID);
		exit(-1);
	}

	short Rcode = received_header->flags & 0x000F;

	if (Rcode == 0) {
		printf("%-3s succeeded with Rcode = %d\n", " ", Rcode);
	}
	else {
		printf("failed with Rcode = %d", Rcode);
		exit(-1);
	}

	int total_records_declared = received_header->answers + received_header->authority + received_header->additional;
	int total_records_parsed = 0;

	int cur_pos_buffer = 12;

	if (received_header->questions > 0) {
		printf("%-4s------------ [questions] ----------\n", " ");
		for (int i = 0; i < received_header->questions; i++) {
			printf("%-10s", " ");
			uint8_t curr_length = (*(uint8_t*)(buf + cur_pos_buffer));
			while (true) {
				char temp_string[MAX_DNS_LENGTH];

				if (curr_length == 0) {
					break;
				}

				strncpy_s(temp_string, buf + cur_pos_buffer + 1, curr_length);
				cur_pos_buffer = cur_pos_buffer + curr_length + 1;
				temp_string[curr_length] = '\0';

				curr_length = (*(uint8_t*)(buf + cur_pos_buffer));


				if (curr_length == 0) {
					std::cout << temp_string;
				}
				else {
					std::cout << temp_string << '.';
				}

				memset(temp_string, 0, sizeof(temp_string));
			}
			cur_pos_buffer += 1;
			QueryHeader* received_query_header = (QueryHeader*)(buf + cur_pos_buffer);
			received_query_header->type = ntohs(*(unsigned short*)(buf + cur_pos_buffer));
			received_query_header->class_name = ntohs(*(unsigned short*)(buf + cur_pos_buffer + 2));
			std::cout << " type " << (received_query_header->type) << " class " << received_query_header->class_name << std::endl;
			cur_pos_buffer += 4;

		}
	}


	if (received_header->answers > 0) {
		printf("%-4s------------ [answers] ----------\n", " ");
		for (int i = 0; i < received_header->answers; i++) {

			if (cur_pos_buffer + 10 > bytesReceived) {
				printf("%-3s ++ invalid record: truncated RR answer header (i.e., don't have the full 10 bytes)\n", " ");
				exit(-1);
			}

			char result[MAX_DNS_LENGTH];
			int result_index = 0;

			int jump_count = 0;
			parseDomainName(buf, bytesReceived, cur_pos_buffer, result, result_index, jump_count);

			DNSanswerHdr* answer = (DNSanswerHdr*)(buf + cur_pos_buffer);
			answer->type = ntohs(*(unsigned short*)(buf + cur_pos_buffer));
			answer->class_name = ntohs(*(unsigned short*)(buf + cur_pos_buffer + 2));
			answer->ttl = ntohl(*(unsigned int*)(buf + cur_pos_buffer + 4));
			answer->len = ntohs(*(unsigned short*)(buf + cur_pos_buffer + 8));

			cur_pos_buffer += 10;

			if (cur_pos_buffer + answer->len > bytesReceived) {
				printf("%-3s ++ invalid record: RR value length stretches the answer beyond packet\n", " ");
				return;
			}

			std::string type = MapType(answer->type);

			if (!(type == "CNAME" || type == "A" || type == "NS" || type == "PTR")) {
				cur_pos_buffer += answer->len;
				continue;
			}
			printf("%-10s", " ");
			std::cout << result << " " << type << " ";

			char parse_type[MAX_DNS_LENGTH];
			int parse_type_index = 0;

			if (answer->type == 1) {
				if (answer->len != 4) {
					printf("%-3s ++ invalid record: incorrect length for A record in authority section\n", " ");
					cur_pos_buffer += answer->len;
					continue;
				}
				for (int j = 0; j < 4; j++) {
					unsigned char ipv4num = (*(unsigned char*)(buf + cur_pos_buffer));
					cur_pos_buffer++;
					if (j == 3) {
						std::cout << (int)ipv4num;
					}
					else {
						std::cout << (int)ipv4num << ".";
					}
				}
			}
			else {
				int jumpCount = 0;
				parseDomainName(buf, bytesReceived, cur_pos_buffer, parse_type, parse_type_index, jumpCount);
				std::cout << parse_type;
			}
			total_records_parsed++;

			std::cout << " TTL: " << answer->ttl << std::endl;

		}


	}

	if (received_header->authority > 0) {
		printf("%-4s------------ [authority] ----------\n", " ");
		for (int i = 0; i < received_header->authority; i++) {
			if (cur_pos_buffer + 10 > bytesReceived) {
				printf("%-3s ++ invalid record: truncated RR answer header in authority section\n", " ");
				exit(-1);
			}
			char result[MAX_DNS_LENGTH];
			int result_index = 0;

			int jump_count = 0;
			parseDomainName(buf, bytesReceived, cur_pos_buffer, result, result_index, jump_count);
			DNSanswerHdr* answer = (DNSanswerHdr*)(buf + cur_pos_buffer);
			answer->type = ntohs(*(unsigned short*)(buf + cur_pos_buffer));
			answer->class_name = ntohs(*(unsigned short*)(buf + cur_pos_buffer + 2));
			answer->ttl = ntohl(*(unsigned int*)(buf + cur_pos_buffer + 4));
			answer->len = ntohs(*(unsigned short*)(buf + cur_pos_buffer + 8));

			cur_pos_buffer += 10;

			if (cur_pos_buffer + answer->len > bytesReceived) {
				printf("%-3s ++ invalid record: RR value length stretches the authority record beyond packet\n", " ");
				return;
			}

			std::string type = MapType(answer->type);

			if (!(type == "CNAME" || type == "A" || type == "NS" || type == "PTR")) {
				cur_pos_buffer += answer->len;
				continue;
			}
			printf("%-10s", " ");
			std::cout << result << " " << type << " ";

			char parse_type[MAX_DNS_LENGTH];
			int parse_type_index = 0;

			if (answer->type == 1) {
				if (answer->len != 4) {
					printf("%-3s ++ invalid record: incorrect length for A record in authority section\n", " ");
					cur_pos_buffer += answer->len;
					exit(-1);
				}
				for (int j = 0; j < 4; j++) {
					unsigned char ipv4num = (*(unsigned char*)(buf + cur_pos_buffer));
					cur_pos_buffer++;
					if (j == 3) {
						std::cout << (int)ipv4num;
					}
					else {
						std::cout << (int)ipv4num << ".";
					}
				}
			}
			else {
				int jumpCount = 0;
				parseDomainName(buf, bytesReceived, cur_pos_buffer, parse_type, parse_type_index, jumpCount);				std::cout << parse_type;
			}
			total_records_parsed++;

			std::cout << " TTL: " << answer->ttl << std::endl;
		}


	}

	if (received_header->additional > 0) {
		printf("%-4s------------ [additional] ----------\n", " ");
		for (int i = 0; i < received_header->additional; i++) {
			if (cur_pos_buffer + 10 > bytesReceived) {
				printf("%-3s ++ invalid record: truncated RR answer header in additional section\n", " ");
				exit(-1);
			}
			char result[MAX_DNS_LENGTH];
			int result_index = 0;

			int jump_count = 0;
			parseDomainName(buf, bytesReceived, cur_pos_buffer, result, result_index, jump_count);
			DNSanswerHdr* answer = (DNSanswerHdr*)(buf + cur_pos_buffer);
			answer->type = ntohs(*(unsigned short*)(buf + cur_pos_buffer));
			answer->class_name = ntohs(*(unsigned short*)(buf + cur_pos_buffer + 2));
			answer->ttl = ntohl(*(unsigned int*)(buf + cur_pos_buffer + 4));
			answer->len = ntohs(*(unsigned short*)(buf + cur_pos_buffer + 8));

			cur_pos_buffer += 10;

			if (cur_pos_buffer + answer->len > bytesReceived) {
				printf("%-3s ++ invalid record: RR value length stretches the authority record beyond packet\n", " ");
				continue;
			}

			std::string type = MapType(answer->type);

			if (!(type == "CNAME" || type == "A" || type == "NS" || type == "PTR")) {
				cur_pos_buffer += answer->len;
				continue;
			}
			printf("%-10s", " ");

			std::cout << result << " " << type << " ";

			char parse_type[MAX_DNS_LENGTH];
			int parse_type_index = 0;

			if (answer->type == 1) {
				if (answer->len != 4) {
					printf("%-3s ++ invalid record: incorrect length for A record in authority section\n", " ");
					cur_pos_buffer += answer->len;
					exit(-1);
				}
				for (int j = 0; j < 4; j++) {
					unsigned char ipv4num = (*(unsigned char*)(buf + cur_pos_buffer));
					cur_pos_buffer++;
					if (j == 3) {
						std::cout << (int)ipv4num;
					}
					else {
						std::cout << (int)ipv4num << ".";
					}
				}
			}
			else {
				int jumpCount = 0;
				parseDomainName(buf, bytesReceived, cur_pos_buffer, parse_type, parse_type_index, jumpCount);
				std::cout << parse_type;
			}
			total_records_parsed++;


			std::cout << " TTL: " << answer->ttl << std::endl;
		}
	}
	if (total_records_parsed < total_records_declared) {
		printf("++ invalid response: not enough records (declared %d but found %d)\n",
			total_records_declared, total_records_parsed);
		exit(-1);
	}

}

void Socket::parseDomainName(char* buf, int bytesReceived, int& cur_pos_buffer, char* result, int& result_index, int jump_count = 0) {
	const int MAX_JUMPS = 12;
	while (true) {
		if (cur_pos_buffer >= bytesReceived) {
			printf("%-3s ++ invalid record: truncated name (packet ends unexpectedly)\n", " ");
			exit(-1);
		}

		uint8_t curr_length = (*(uint8_t*)(buf + cur_pos_buffer));

		if (curr_length == 0) {
			result[result_index] = '\0';
			cur_pos_buffer++;
			return;
		}

		if ((curr_length & 0xC0) == 0xC0) {
			if (cur_pos_buffer + 1 >= bytesReceived) {
				printf("%-3s ++ invalid record: truncated jump offset\n", " ");
				exit(-1);
			}

			uint16_t offset = ntohs(*(uint16_t*)(buf + cur_pos_buffer)) & 0x3FFF;
			cur_pos_buffer += 2;

			if (++jump_count > MAX_JUMPS) {
				printf("%-3s ++ invalid record: jump loop\n", " ");
				exit(-1);
			}

			if (offset >= bytesReceived) {
				printf("%-3s ++ invalid record: jump beyond packet boundary\n", " ");
				exit(-1);
			}
			else if (offset < 12) {
				printf("%-3s ++ invalid record: jump into fixed DNS header\n", " ");
				exit(-1);
			}

			if (result_index > 0 && result[result_index - 1] != '.') {
				result[result_index++] = '.';
			}

			int temp_pos = offset;
			parseDomainName(buf, bytesReceived, temp_pos, result, result_index, jump_count);
			return;
		}
		else {
			if (cur_pos_buffer + curr_length + 1 > bytesReceived) {
				printf("%-3s ++ invalid record: truncated name\n", " ");
				return;
			}

			if (result_index > 0 && result[result_index - 1] != '.') {
				result[result_index++] = '.';
			}


			strncpy(result + result_index, buf + cur_pos_buffer + 1, curr_length);
			cur_pos_buffer += curr_length + 1;
			result_index += curr_length;
		}
	}
}


std::string Socket::MapType(int type) {
	if (type == 1) {
		return "A";
	}
	else if (type == 2) {
		return "NS";
	}
	else if (type == 5) {
		return "CNAME";
	}
	else if (type == 12) {
		return "PTR";
	}
	else {
		return " ";
	}
}




Socket::~Socket() {
	closesocket(sock);
	WSACleanup();
}