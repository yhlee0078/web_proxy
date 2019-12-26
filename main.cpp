#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <inttypes.h>
#include <resolv.h>
#include <netdb.h>
#include <iostream>
#include <thread>
#include <mutex>
#include <vector>

#define TCP_PORT 80
#define CLIENT 1
#define SERVER 2
using namespace std;

mutex m;
vector<pair<char*, int>> sk;

int setup_socket(uint16_t port, uint32_t ip_addr, int side) 
{
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd == -1) 
		{
                perror("socket failed");
                exit(-1);
        }

        int optval = 1;
        setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,  &optval , sizeof(int));
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(TCP_PORT);
        addr.sin_addr.s_addr = htonl(ip_addr);
        memset(addr.sin_zero, 0, sizeof(addr.sin_zero));

	if(side == CLIENT) 
	{
		int res = connect(sockfd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(struct sockaddr));
	        if (res == -1) 
			{
        	        perror("connect failed");
	                exit(-1);
	        }
        	printf("connected\n");
	}
	else if (side == SERVER) 
	{
		setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,  &optval , sizeof(int));
		int res = bind(sockfd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(struct sockaddr));
	        if (res == -1) 
			{
	                perror("bind failed");
        	        exit(-1);
	        }

        	res = listen(sockfd, 2);
	        if (res == -1) 
			{
        	        perror("listen failed");
	                exit(-1);
	        }
	}

	return sockfd;
}

void str_to_uint16(char* str, uint16_t* ret) 
{
    char *end;
    intmax_t val = strtoimax(str, &end, 10);
    *ret = (uint16_t) val;
    return;
}

void str_to_uint32(char* str, uint16_t* ret) 
{
    char *end;
    intmax_t val = strtoimax(str, &end, 10);
    *ret = (uint32_t) val;
    return;
}


void dump_str(char* buf) 
{
	for(int i = 0; i < strlen(buf); i++) 
	{
		printf("%02x ", buf[i]);
		if((i + 1) % 16 == 0) printf("\n");
	}
	printf("\n");
}

void srv_to_cli(int fd, int web_fd) 
{
	while(true) {
		const static int BUFSIZE = 1024;
		char buf[BUFSIZE];
		ssize_t received = recv(web_fd, buf, BUFSIZE - 1, 0);
	        printf("web to client msg: ");
	        dump_str(buf);
	        if (received == 0 || received == -1) {
	                perror("recv failed");
	                break;
	        }
		ssize_t sent = send(fd, buf, strlen(buf), 0);
	}
}

void host_check(char *data, char *captured_host) 
{
	uint8_t ip_header_length, tcp_header_length;
	ip_header_length = (data[0] & 0x0F) * 4;
	tcp_header_length = ((data[ip_header_length + 12] & 0xF0) >> 4) * 4;
	int http_offset = ip_header_length + tcp_header_length;
	int k;
	char method[6][10] = {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"};
	
	//check tcp segment is http
	for(k = 0; k < 6; k++) {
		if(!memcmp(data + http_offset, method[k], strlen(method[k]))){
			break;
		}	
	}
	int i = 0;
	int j = 0;
	if(k != 6) 
	{
		while(1) 
		{
			if(!memcmp(data + http_offset + i, "Host: ", 6)) 
			{
				i += 6;
				int length = 0;
				while(1) 
				{
					if(!memcmp(data + http_offset + i, "\r\n", 2)) 
					{
						break;
					}
					captured_host[j] = data[http_offset + i];
					i++;
					j++;
				}
				break;
			}
			i++;
		}
	}
	return;
}

void cli_to_srv(int fd) 
{
	vector<pair <char*, int>> sk;
	while(true) {
                const static int BUFSIZE = 1024;
                char buf[BUFSIZE];
                ssize_t received = recv(fd, buf, BUFSIZE - 1, 0);
		printf("client to web msg: ");
		dump_str(buf);
                if (received == 0 || received == -1) {
                       perror("recv failed");
                       break;
        	}
		char* host;
		host_check(buf, host);
		bool flg = false;
		m.lock();
		for(vector<pair <char*, int>>::iterator it = sk.begin();
		it != sk.end();
		it++){
			if(!strncmp(host, it->first, strlen(host))) {
			        ssize_t sent = send(it->second, buf, strlen(buf), 0);
				if(sent == 0) {
					perror("send failed");
				}
				flg = true;
				thread t(srv_to_cli, fd, it->second);
				t.detach();
				break;
			}
		}
		m.unlock();
		if(flg) continue;
		else {
			addrinfo *addr_info;
			addrinfo hint = {0};
			hint.ai_flags = AI_NUMERICHOST;
			hint.ai_family = AF_INET;
			hint.ai_socktype = SOCK_STREAM;
			hint.ai_protocol = IPPROTO_TCP;
 			if(getaddrinfo(host, "80", &hint, &addr_info) != 0) {
				perror("error during getting ip addr info");
				freeaddrinfo(addr_info);
				continue;
			}
			uint32_t ip_addr;
			memcpy(&ip_addr, &(((struct sockaddr_in *)(addr_info->ai_addr))->sin_addr), sizeof(ip_addr));
			int web_fd = setup_socket(TCP_PORT, ip_addr, CLIENT);
			freeaddrinfo(addr_info);
			m.lock();
			pair<char*, int> p(host, web_fd);
			sk.push_back(p);
			m.unlock();
			ssize_t sent = send(web_fd, buf, strlen(buf), 0);
			m.unlock();
			if (sent == 0) {
				perror("send failed");
				break;
			}
			thread t(srv_to_cli, fd, web_fd);
			t.detach();
		}
	}
}



int main(int argc, char* argv[]) {
	if(argc != 2) 
	{
		printf("syntax: web_proxy <tcp port>\n");
		printf("sample : web_proxy 8080\n");
		printf("no ssl sorry");
		exit(-1);
	}
	uint16_t tcp_port;
	str_to_uint16(argv[1], &tcp_port);
	int sockfd = setup_socket(tcp_port, INADDR_ANY, SERVER);
        while (true) 
		{
                struct sockaddr_in addr;
                socklen_t clientlen = sizeof(sockaddr);
                int child = accept(sockfd, reinterpret_cast<struct sockaddr*>(&addr), &clientlen);

		if(child < 0) 
		{
			perror("Error on accpet");
			break;
		}
		thread t(cli_to_srv, sockfd);

		t.detach();
	}
	close(sockfd);
	return 0;
}
