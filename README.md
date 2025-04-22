# DNS Lookup and Response Parser

A custom recursive DNS client implemented in C++ using raw UDP sockets. This system constructs binary DNS queries, sends them directly to DNS servers, and parses the response headers and sections in compliance with RFC 1035. It supports both hostname and IP address resolution, with built-in retransmission, timeout handling, and error classification.

## Academic Context

This project was developed as part of CSCE 463 (Networks and Distributed Processing) at Texas A&M University under Professor Dmitri Loguinov. It is shared for educational and reference purposes. Please respect academic integrity if currently enrolled in the course.

**Course Details:**
- Course: CSCE 463 - Networks and Distributed Processing
- Focus: DNS Protocol Internals, Packet Parsing, UDP Transport, Fault Tolerance

## Technical Features

- **Raw DNS Query Construction**:
  - Encodes DNS headers and question records in binary format
  - Supports standard forward (A) and reverse (PTR) lookups
  - Generates unique TXIDs and tracks them through the response

- **UDP Socket Communication**:
  - Uses raw WinSock UDP sockets with binding to ephemeral ports
  - Implements retry logic with timeouts (up to 3 attempts)

- **Binary Response Parsing**:
  - Parses and validates fixed DNS headers
  - Extracts answers, authorities, and additional records (A, NS, PTR, CNAME)
  - Handles compression via pointer-based jumps in domain names

- **Error Detection and Robustness**:
  - Detects and reports malformed or corrupted packets (e.g., jump loops, truncated names, header mismatches)
  - Differentiates between RCODE errors, socket failures, and timeout events

## Core Components

- C++ binary-level memory manipulation (struct packing, bit flags)
- Custom parsing logic for:
  - Question section
  - Answer/Authority/Additional records
- Domain name decompression using pointer resolution
- Lookup type inference via `inet_addr()`

## Technologies

- C++
- WinSock API
- Windows Threading and Networking
- RFC 1035 DNS Packet Structure

## Building and Usage

```bash
# Build using Visual Studio 2022
# Usage format:
hw2.exe <domain-or-ip> <dns-server-ip>

# Examples:
hw2.exe www.google.com 8.8.8.8
