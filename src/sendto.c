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
    // FIX: Ignora pragma su MinGW/GCC
    #ifdef _MSC_VER
    #pragma comment(lib, "ws2_32.lib")
    #endif
    #define close closesocket
#else
    #include <unistd.h>
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <sys/socket.h>
    #include <sys/time.h>
    #define SOCKET int
    #define INVALID_SOCKET -1
#endif

int main(int argc, char **argv) {
#ifdef _WIN32
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
#endif

    struct sockaddr_in6 addr;
    char buf[65536];
    int port = 3333;
    const char *target_ip = "::1";

    if(argc > 1) port = atoi(argv[1]);
    if(argc > 2) target_ip = argv[2]; // Supporto IP target opzionale

    SOCKET sd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sd == INVALID_SOCKET) {
        perror("socket");
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(port);
    if (inet_pton(AF_INET6, target_ip, &addr.sin6_addr) <= 0) {
        // Fallback IPv4 mapped su IPv6 se l'input è IPv4 puro
        // Ma per semplicità proviamo a parsarlo come v4 se v6 fallisce, 
        // oppure l'utente deve passare ::ffff:127.0.0.1
        fprintf(stderr, "Invalid IP address: %s (Use IPv6 or ::ffff:IPv4)\n", target_ip);
        return 1;
    }

    const char *msg = "PING";
    if (argc > 3) msg = argv[3]; // Messaggio custom

    sendto(sd, msg, strlen(msg), 0, (struct sockaddr *)&addr, sizeof(addr));
    printf("Sent: '%s' to [%s]:%d\n", msg, target_ip, port);

    // Timeout
    #ifdef _WIN32
    DWORD timeout = 2000;
    setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    #else
    struct timeval tv = {2, 0};
    setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    #endif

    struct sockaddr_in6 from;
    socklen_t flen = sizeof(from);
    int n = recvfrom(sd, buf, sizeof(buf)-1, 0, (struct sockaddr *)&from, &flen);
    if(n > 0) {
        buf[n] = 0;
        printf("Reply: %s\n", buf);
    } else {
        printf("Timeout waiting for reply.\n");
    }

    close(sd);
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
