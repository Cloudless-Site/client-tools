// Copyright 2026 Marco Guarducci
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//     http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    // FIX: Ignora pragma su MinGW/GCC, serve solo per MSVC
    #ifdef _MSC_VER
    #pragma comment(lib, "ws2_32.lib")
    #endif
    #define close closesocket
#else
    #include <unistd.h>
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <sys/socket.h>
    #define SOCKET int
    #define INVALID_SOCKET -1
#endif

int main(int argc, char **argv) {
#ifdef _WIN32
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
#endif

    struct sockaddr_in6 addr, client;
    socklen_t len = sizeof(client);
    char buf[65536];
    int port = 3333;

    if(argc > 1) port = atoi(argv[1]);

    SOCKET sd = socket(AF_INET6, SOCK_DGRAM, 0);
    int no = 0;
#ifdef _WIN32
    setsockopt(sd, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&no, sizeof(no));
#else
    setsockopt(sd, IPPROTO_IPV6, IPV6_V6ONLY, &no, sizeof(no));
#endif

    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_any;
    addr.sin6_port = htons(port);

    if (bind(sd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind failed");
        return 1;
    }
    printf("Echo UDP on port %d (IPv4/IPv6)\n", port);

    for(;;) {
        int n = recvfrom(sd, buf, sizeof(buf)-1, 0, (struct sockaddr *)&client, &len);
        if(n > 0) {
            buf[n] = 0;
            printf("Got %d bytes: %s\n", n, buf);
            sendto(sd, buf, n, 0, (struct sockaddr *)&client, len);
        }
    }
    
#ifdef _WIN32
    closesocket(sd);
    WSACleanup();
#endif
    return 0;
}
